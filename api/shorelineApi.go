package api

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"./../clients"
	"./../models"
	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common/clients/highwater"
	"github.com/tidepool-org/go-common/clients/status"
)

type (
	Api struct {
		Store   clients.StoreClient
		Config  Config
		metrics highwater.Client
	}
	Config struct {
		ServerSecret string `json:"serverSecret"` //used for services
		LongTermKey  string `json:"longTermKey"`
		Salt         string `json:"salt"`      //used for pw
		Secret       string `json:"apiSecret"` //used for token
	}
	varsHandler func(http.ResponseWriter, *http.Request, map[string]string)
)

const (
	TP_SERVER_NAME               = "x-tidepool-server-name"
	TP_SERVER_SECRET             = "x-tidepool-server-secret"
	TP_SESSION_TOKEN             = "x-tidepool-session-token"
	TP_TOKEN_DURATION            = "tokenduration"
	STATUS_NO_USR_DETAILS        = "No user details were given"
	STATUS_ERR_FINDING_USR       = "Error finding user"
	STATUS_ERR_CREATING_USR      = "Error creating the user"
	STATUS_ERR_UPDATING_USR      = "Error updating user"
	STATUS_USR_ALREADY_EXISTS    = "User aleady exists"
	STATUS_ERR_GENTERATING_TOKEN = "Error generating the token"
	STATUS_ERR_UPDATING_TOKEN    = "Error updating token"
	STATUS_MISSING_USR_DETAILS   = "Not all required details were given"
	STATUS_ERROR_UPDATING_PW     = "Error updating password"
	STATUS_MISSING_ID_PW         = "Missing id and/or password"
	STATUS_NO_MATCH              = "No user matched the given details"
	STATUS_NO_TOKEN_MATCH        = "No token matched the given details"
	STATUS_PW_WRONG              = "Wrong password"
	STATUS_ERR_SENDING_EMAIL     = "Error sending email"
	STATUS_NO_TOKEN              = "No x-tidepool-session-token was found"
)

func InitApi(cfg Config, store clients.StoreClient, metrics highwater.Client) *Api {
	return &Api{
		Store:   store,
		Config:  cfg,
		metrics: metrics,
	}
}

func (a *Api) SetHandlers(prefix string, rtr *mux.Router) {

	rtr.HandleFunc("/status", a.GetStatus).Methods("GET")

	rtr.Handle("/user", varsHandler(a.GetUserInfo)).Methods("GET")
	rtr.Handle("/user/{userid}", varsHandler(a.GetUserInfo)).Methods("GET")

	rtr.HandleFunc("/user", a.CreateUser).Methods("POST")
	rtr.Handle("/user", varsHandler(a.UpdateUser)).Methods("PUT")
	rtr.Handle("/user/{userid}", varsHandler(a.UpdateUser)).Methods("PUT")
	rtr.Handle("/user/{userid}", varsHandler(a.DeleteUser)).Methods("DELETE")

	rtr.HandleFunc("/login", a.Login).Methods("POST")
	rtr.HandleFunc("/login", a.RefreshSession).Methods("GET")
	rtr.Handle("/login/{longtermkey}", varsHandler(a.LongtermLogin)).Methods("POST")

	rtr.HandleFunc("/serverlogin", a.ServerLogin).Methods("POST")

	rtr.Handle("/token/{token}", varsHandler(a.ServerCheckToken)).Methods("GET")

	rtr.HandleFunc("/logout", a.Logout).Methods("POST")

	rtr.HandleFunc("/private", a.AnonymousIdHashPair).Methods("GET")
	rtr.Handle("/private/{userid}/{key}", varsHandler(a.ManageIdHashPair)).Methods("GET", "POST", "PUT", "DELETE")

}

func (h varsHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	h(res, req, vars)
}

//Docode the http.Request parsing out the user details
func getUserDetail(req *http.Request) (ud *models.UserDetail) {
	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&ud); err != nil {
			log.Println("error trying to decode user detail ", err)
			return ud
		}
	}
	log.Printf("User details [%v]", ud)
	return ud
}

//Docode the http.Request parsing out the user details
func getGivenDetail(req *http.Request) (d map[string]string) {
	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&d); err != nil {
			log.Println("error trying to decode user detail ", err)
			return nil
		}
	}
	return d
}

//send metric
func (a *Api) logMetric(name, token string, params map[string]string) {
	if token == "" {
		log.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	log.Printf("log metric name[%s] params[%v]", name, params)
	a.metrics.PostThisUser(name, token, params)
}

//send metric
func (a *Api) logMetricAsServer(name, token string, params map[string]string) {
	if token == "" {
		log.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	log.Printf("log metric as server name[%s] params[%v]", name, params)
	a.metrics.PostServer(name, token, params)
}

//send metric
func (a *Api) logMetricForUser(id, name, token string, params map[string]string) {
	if token == "" {
		log.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	log.Printf("log metric id[%s] name[%s] params[%v]", id, name, params)
	a.metrics.PostWithUser(id, name, token, params)
}

//get the token from the req header
func (a *Api) getUnpackedToken(tokenString string) *models.TokenData {
	if st := models.GetSessionToken(tokenString); st.Id != "" {
		if td := st.UnpackAndVerify(a.Config.Secret); td != nil && td.Valid == true {
			return td
		}
	}
	return nil
}

//has a duration been set?
func tokenDuration(req *http.Request) (dur float64) {

	durString := req.Header.Get(TP_TOKEN_DURATION)

	if durString != "" {
		dur, _ = strconv.ParseFloat(durString, 64)
	}

	return dur
}

// Extract the username and password from the authorization
// line of an HTTP header. This function will handle the
// parsing and decoding of the line.
func unpackAuth(authLine string) (usr *models.User, pw string) {
	if authLine != "" {
		parts := strings.SplitN(authLine, " ", 2)
		payload := parts[1]
		if decodedPayload, err := base64.URLEncoding.DecodeString(payload); err != nil {
			log.Print("Error unpacking authorization header [%s]", err.Error())
		} else {
			details := strings.Split(string(decodedPayload), ":")
			if details[0] != "" || details[1] != "" {
				//Note the incoming `name` coule infact be id, email or the username
				return models.UserFromDetails(&models.UserDetail{Id: details[0], Name: details[0], Emails: []string{details[0]}}), details[1]
			}
		}
	}
	return nil, ""
}

func sendModelsAsRes(res http.ResponseWriter, models ...interface{}) {

	res.Header().Set("content-type", "application/json")
	res.WriteHeader(http.StatusOK)

	res.Write([]byte("["))
	for i := range models {
		if jsonDetails, err := json.Marshal(models[i]); err != nil {
			log.Println(err)
		} else {
			res.Write(jsonDetails)
		}
	}
	res.Write([]byte("]"))
	return
}

func sendModelAsRes(res http.ResponseWriter, model interface{}) {
	sendModelAsResWithStatus(res, model, http.StatusOK)
	return
}

func sendModelAsResWithStatus(res http.ResponseWriter, model interface{}, statusCode int) {
	res.Header().Set("content-type", "application/json")
	res.WriteHeader(statusCode)

	if jsonDetails, err := json.Marshal(model); err != nil {
		log.Println(err)
	} else {
		res.Write(jsonDetails)
	}
	return
}

func (a *Api) hasServerToken(tokenString string) bool {

	if td := a.getUnpackedToken(tokenString); td != nil {
		return td.IsServer
	}
	return false
}

func (a *Api) createAndSaveToken(dur float64, id string, isServer bool) (*models.SessionToken, error) {
	sessionToken, _ := models.NewSessionToken(
		&models.TokenData{
			UserId:       id,
			IsServer:     isServer,
			DurationSecs: dur,
		},
		a.Config.Secret,
	)

	if err := a.Store.AddToken(sessionToken); err == nil {
		return sessionToken, nil
	} else {
		return nil, err
	}
}

func (a *Api) GetStatus(res http.ResponseWriter, req *http.Request) {
	if err := a.Store.Ping(); err != nil {
		log.Println(err)
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(err.Error()))
		return
	}
	res.WriteHeader(http.StatusOK)
	return
}

// status: 201 User
// status: 400 STATUS_MISSING_USR_DETAILS
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_GENTERATING_TOKEN
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if usrDetails := getUserDetail(req); usrDetails != nil {

		if usr, err := models.NewUser(usrDetails, a.Config.Salt); err == nil {
			//they shouldn't already exist
			if results, _ := a.Store.FindUsers(usr); results == nil || len(results) == 0 {

				if err := a.Store.UpsertUser(usr); err != nil {
					log.Printf("CreateUser %s err[%s]", STATUS_ERR_CREATING_USR, err.Error())
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_CREATING_USR), http.StatusInternalServerError)
					return
				}
				if sessionToken, err := a.createAndSaveToken(tokenDuration(req), usr.Id, false); err != nil {
					log.Printf("CreateUser %s err[%s]", STATUS_ERR_GENTERATING_TOKEN, err.Error())
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENTERATING_TOKEN), http.StatusInternalServerError)
					return
				} else {
					a.logMetric("usercreated", sessionToken.Id, nil)
					res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
					sendModelAsResWithStatus(res, usr, http.StatusCreated)
					return
				}
			} else {
				log.Printf("CreateUser %s ", STATUS_USR_ALREADY_EXISTS)
				sendModelAsResWithStatus(res, status.NewStatus(http.StatusConflict, STATUS_USR_ALREADY_EXISTS), http.StatusConflict)
				return
			}
		} else {
			log.Printf("CreateUser %s ", err.Error())
		}
	}
	//incoming details were bad
	log.Printf("CreateUser %s ", STATUS_MISSING_USR_DETAILS)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_USR_DETAILS), http.StatusBadRequest)
	return
}

// status: 200
// status: 400 STATUS_NO_USR_DETAILS
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_FINDING_USR
// status: 500 STATUS_ERR_UPDATING_USR
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if td := a.getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN)); td != nil {

		var (
			id string
			//structure that the update are given to us in
			updatesToApply struct {
				Updates *models.UserDetail `json:"updates"`
			}
		)

		id = vars["userid"]

		if id == "" {
			id = td.UserId
		}

		if id != "" { // get out quick

			if req.ContentLength > 0 {
				_ = json.NewDecoder(req.Body).Decode(&updatesToApply)
			}

			if updatesToApply.Updates != nil {

				usrToFind := models.UserFromDetails(&models.UserDetail{Id: id, Emails: []string{id}})

				if userToUpdate, err := a.Store.FindUser(usrToFind); err != nil {
					log.Printf("UpdateUser %s err[%s]", STATUS_ERR_FINDING_USR, err.Error())
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
					return
				} else if userToUpdate != nil {

					//Name and/or Emails and perform dups check
					if updatesToApply.Updates.Name != "" || len(updatesToApply.Updates.Emails) > 0 {
						dupCheck := models.UserFromDetails(&models.UserDetail{})
						if updatesToApply.Updates.Name != "" {
							userToUpdate.Name = updatesToApply.Updates.Name
							dupCheck.Name = userToUpdate.Name
						}
						if len(updatesToApply.Updates.Emails) > 0 {
							userToUpdate.Emails = updatesToApply.Updates.Emails
							dupCheck.Emails = userToUpdate.Emails
						}
						//check if unique
						if results, err := a.Store.FindUsers(dupCheck); err != nil {
							log.Printf("UpdateUser %s err[%s]", STATUS_ERR_FINDING_USR, err.Error())
							sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
							return
						} else if len(results) > 0 {
							log.Printf("UpdateUser %s ", STATUS_USR_ALREADY_EXISTS)
							sendModelAsResWithStatus(res, status.NewStatus(http.StatusConflict, STATUS_USR_ALREADY_EXISTS), http.StatusConflict)
							return
						}
					}
					//Rehash the pw if needed
					if updatesToApply.Updates.Pw != "" {

						if err := userToUpdate.HashPassword(updatesToApply.Updates.Pw, a.Config.Salt); err != nil {
							log.Printf("UpdateUser %s err[%s]", STATUS_ERR_UPDATING_USR, err.Error())
							sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR), http.StatusInternalServerError)
							return
						}
					}
					//All good - now update
					if err := a.Store.UpsertUser(userToUpdate); err != nil {
						log.Printf("UpdateUser %s err[%s]", STATUS_ERR_UPDATING_USR, err.Error())
						sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR), http.StatusInternalServerError)
						return
					} else {
						if td.IsServer {
							a.logMetricForUser(id, "userupdated", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "true"})
						} else {
							a.logMetric("userupdated", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "false"})
						}
						res.WriteHeader(http.StatusOK)
						return
					}
				}
			}
		}
		log.Printf("UpdateUser %s ", STATUS_NO_USR_DETAILS)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_NO_USR_DETAILS), http.StatusBadRequest)
		return
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

//Pull the incoming user feilds to search for from http.Request body and
//find any matches returning them with return http.StatusOK
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if td := a.getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN)); td != nil {

		var usr *models.User

		id := vars["userid"]
		if id != "" {
			//the `userid` could infact be an email
			usr = models.UserFromDetails(&models.UserDetail{Id: id, Emails: []string{id}})
		} else {
			//use the token to find the userid
			usr = models.UserFromDetails(&models.UserDetail{Id: td.UserId})
		}

		if usr == nil {
			res.WriteHeader(http.StatusBadRequest)
			res.Write([]byte(STATUS_NO_USR_DETAILS))
			return
		} else {
			if results, err := a.Store.FindUsers(usr); err != nil {
				log.Println(err)
				res.WriteHeader(http.StatusInternalServerError)
				res.Write([]byte(STATUS_ERR_FINDING_USR))
				return
			} else if results != nil {

				if td.IsServer {
					a.logMetricForUser(id, "getuserinfo", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "true"})
				} else {
					a.logMetric("getuserinfo", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "false"})
				}

				/*
					TODO: sort this out
					if len(results) == 1 && usr.Pw != "" {
						if results[0].PwsMatch(usr, a.Config.Salt) {
							sendModelAsRes(res, results[0])
							return
						} else {
							res.WriteHeader(http.StatusNoContent)
							return
						}
					} else*/
				if len(results) == 1 {
					sendModelAsRes(res, results[0])
					return
				}
				sendModelsAsRes(res, results)
				return
			}
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) DeleteUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if td := a.getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN)); td != nil {

		var id string
		if td.IsServer == true {
			id = vars["userid"]
		} else {
			id = td.UserId
		}

		pw := getGivenDetail(req)["password"]

		if id != "" && pw != "" {

			var err error
			toDelete := models.UserFromDetails(&models.UserDetail{Id: id})

			if err = toDelete.HashPassword(pw, a.Config.Salt); err == nil {
				if err = a.Store.RemoveUser(toDelete); err == nil {

					if td.IsServer {
						a.logMetricForUser(id, "deleteuser", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "true"})
					} else {
						a.logMetric("deleteuser", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "false"})
					}

					//cleanup if any
					if td.IsServer == false {
						usrToken := &models.SessionToken{Id: req.Header.Get(TP_SESSION_TOKEN)}
						a.Store.RemoveToken(usrToken)
					}
					//all good
					res.WriteHeader(http.StatusAccepted)
					return
				}
			}
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			return
		}
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusForbidden, STATUS_MISSING_ID_PW), http.StatusForbidden)
		return

	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

// status: 200 TP_SESSION_TOKEN,
// status: 204 STATUS_NO_MATCH
// status: 400 STATUS_MISSING_ID_PW
// status: 401 STATUS_PW_WRONG
// status: 500 STATUS_ERR_FINDING_USR
// status: 500 STATUS_ERR_UPDATING_TOKEN
func (a *Api) Login(res http.ResponseWriter, req *http.Request) {
	if usr, pw := unpackAuth(req.Header.Get("Authorization")); usr != nil {

		if results, err := a.Store.FindUsers(usr); err != nil {
			log.Printf("Error trying to find user when logging in [%s]", err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
			return
		} else {
			if len(results) > 0 {
				for i := range results {
					//ensure a pw match
					if results[i] != nil && results[i].PwsMatch(pw, a.Config.Salt) {
						//a match so login
						if sessionToken, err := a.createAndSaveToken(
							tokenDuration(req),
							results[i].Id,
							false,
						); err != nil {
							log.Printf("Error trying to update the users token [%s]", err.Error())
							sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN), http.StatusInternalServerError)
							return
						} else {
							a.logMetric("userlogin", sessionToken.Id, nil)
							res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
							sendModelAsRes(res, results[i])
							return
						}
					}
					//hmmm
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
					return
				}
			} else {
				sendModelAsResWithStatus(res, status.NewStatus(http.StatusNoContent, STATUS_NO_MATCH), http.StatusNoContent)
				return
			}
		}
	}
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_ID_PW), http.StatusBadRequest)
	return
}

// status: 200 TP_SESSION_TOKEN
// status: 400 STATUS_MISSING_ID_PW
// status: 401 STATUS_PW_WRONG
// status: 500 STATUS_ERR_UPDATING_TOKEN
func (a *Api) ServerLogin(res http.ResponseWriter, req *http.Request) {

	server, pw := req.Header.Get(TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)

	if server == "" || pw == "" {
		log.Print("ServerLogin " + STATUS_MISSING_ID_PW)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_ID_PW), http.StatusBadRequest)
		return
	}
	if pw == a.Config.ServerSecret {
		//generate new token
		if sessionToken, err := a.createAndSaveToken(
			tokenDuration(req),
			server,
			true,
		); err != nil {
			log.Printf("ServerLogin %s err[%s]", STATUS_MISSING_ID_PW, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENTERATING_TOKEN), http.StatusInternalServerError)
			return
			return
		} else {
			a.logMetricAsServer("serverlogin", sessionToken.Id, nil)
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
			return
		}
	}
	log.Printf("ServerLogin %s ", STATUS_PW_WRONG)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
	return
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 500 STATUS_ERR_GENTERATING_TOKEN
func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	if td := a.getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN)); td != nil {
		const TWO_HOURS_IN_SECS = 60 * 60 * 2

		if td.IsServer == false && td.DurationSecs > TWO_HOURS_IN_SECS {
			//long-duration, it's not renewable, so just return it
			sendModelAsRes(res, td)
			return
		}
		//refresh
		if sessionToken, err := a.createAndSaveToken(
			tokenDuration(req),
			td.UserId,
			td.IsServer,
		); err != nil {
			log.Printf("RefreshSession %s err[%s]", STATUS_ERR_GENTERATING_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENTERATING_TOKEN), http.StatusInternalServerError)
			return
		} else {
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
			sendModelAsRes(res, td)
			return
		}

	}
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
	return
}

// Set the longeterm duration and then process as per Login
// note: see Login for return codes
func (a *Api) LongtermLogin(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	const (
		THIRTY_DAYS = 30 * 24 * 60 * 60
	)
	longtermkey := vars["longtermkey"]

	if longtermkey == a.Config.LongTermKey {
		req.Header.Add(TP_TOKEN_DURATION, string(THIRTY_DAYS))
	}

	//and now login
	a.Login(res, req)
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 404 STATUS_NO_TOKEN_MATCH
func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if a.hasServerToken(req.Header.Get(TP_SESSION_TOKEN)) {
		tokenString := vars["token"]

		svrToken := &models.SessionToken{Id: tokenString}
		if td := svrToken.UnpackAndVerify(a.Config.Secret); td != nil && td.Valid {
			sendModelAsRes(res, td)
			return
		}
		log.Printf("ServerCheckToken %s", STATUS_NO_TOKEN_MATCH)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusNotFound, STATUS_NO_TOKEN_MATCH), http.StatusNotFound)
		return
	}
	log.Printf("ServerCheckToken %s", STATUS_NO_TOKEN)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
	return
}

// status: 200
func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	//lets just try and remove the token
	st := models.GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))
	if st.Id != "" {
		if err := a.Store.RemoveToken(st); err != nil {
			log.Printf("Logout  was unable to delete token err[%s]", err.Error())
		}
	}
	//otherwise all good
	res.WriteHeader(http.StatusOK)
	return
}

func (a *Api) AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	idHashPair := models.NewAnonIdHashPair([]string{a.Config.Salt}, req.URL.Query())
	sendModelAsRes(res, idHashPair)
	return
}

func (a *Api) ManageIdHashPair(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	//we need server token
	if a.hasServerToken(req.Header.Get(TP_SESSION_TOKEN)) {

		usr := models.UserFromDetails(&models.UserDetail{Id: vars["userid"]})
		theKey := vars["key"]

		baseStrings := []string{a.Config.Salt, usr.Id, theKey}

		if foundUsr, err := a.Store.FindUser(usr); err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(STATUS_ERR_FINDING_USR))
			return
		} else {

			a.logMetricForUser(usr.Id, "manageprivatepair", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"verb": req.Method})

			switch req.Method {
			case "GET":
				if foundUsr.Private != nil && foundUsr.Private[theKey] != nil {
					sendModelAsRes(res, foundUsr.Private[theKey])
					return
				} else {
					if foundUsr.Private == nil {
						foundUsr.Private = make(map[string]*models.IdHashPair)
					}
					foundUsr.Private[theKey] = models.NewIdHashPair(baseStrings, req.URL.Query())

					if err := a.Store.UpsertUser(foundUsr); err != nil {
						log.Println(err)
						res.Write([]byte(STATUS_ERR_UPDATING_USR))
						res.WriteHeader(http.StatusInternalServerError)
						return
					} else {
						sendModelAsRes(res, foundUsr.Private[theKey])
						return
					}
				}
			case "POST", "PUT":
				if foundUsr.Private == nil {
					foundUsr.Private = make(map[string]*models.IdHashPair)
				}
				foundUsr.Private[theKey] = models.NewIdHashPair(baseStrings, req.URL.Query())

				if err := a.Store.UpsertUser(foundUsr); err != nil {
					log.Println(err)
					res.Write([]byte(STATUS_ERR_UPDATING_USR))
					res.WriteHeader(http.StatusInternalServerError)
					return
				} else {
					sendModelAsResWithStatus(res, foundUsr.Private[theKey], http.StatusCreated)
					return
				}
			case "DELETE":
				res.WriteHeader(http.StatusNotImplemented)
				return
			}
			res.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}
