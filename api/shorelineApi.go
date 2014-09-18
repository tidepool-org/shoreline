package api

import (
	"./../clients"
	"./../models"
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type (
	Api struct {
		Store  clients.StoreClient
		Config Config
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
	STATUS_PW_WRONG              = "Wrong password"
	STATUS_ERR_SENDING_EMAIL     = "Error sending email"
)

func InitApi(cfg Config, store clients.StoreClient) *Api {
	return &Api{
		Store:  store,
		Config: cfg,
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
			log.Print(err)
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

//Pull the incoming user from the http.Request body and save return http.StatusCreated
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if usrDetails := getUserDetail(req); usrDetails != nil {

		if usr, err := models.NewUser(usrDetails, a.Config.Salt); err == nil {
			//do they already exist??
			if results, _ := a.Store.FindUsers(usr); results == nil || len(results) == 0 {

				if err := a.Store.UpsertUser(usr); err != nil {
					log.Println(err)
					res.WriteHeader(http.StatusInternalServerError)
					res.Write([]byte(STATUS_ERR_CREATING_USR))
					return
				}
				if sessionToken, err := a.createAndSaveToken(tokenDuration(req), usr.Id, false); err != nil {
					log.Println(err)
					res.WriteHeader(http.StatusInternalServerError)
					res.Write([]byte(STATUS_ERR_GENTERATING_TOKEN))
					return
				} else {
					res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
					sendModelAsResWithStatus(res, usr, http.StatusCreated)
					return
				}
			} else {
				res.WriteHeader(http.StatusConflict)
				res.Write([]byte(STATUS_USR_ALREADY_EXISTS))
				return
			}
		} else {
			log.Println(err)
		}
	}
	//incoming details were bad
	res.WriteHeader(http.StatusBadRequest)
	res.Write([]byte(STATUS_MISSING_USR_DETAILS))
	return
}

//Pull the incoming user updates from http.Request body and save return http.StatusOK
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
					log.Println(err)
					res.WriteHeader(http.StatusInternalServerError)
					res.Write([]byte(STATUS_ERR_FINDING_USR))
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
							log.Println(err)
							res.WriteHeader(http.StatusInternalServerError)
							return
						} else if len(results) > 0 {
							log.Println(STATUS_USR_ALREADY_EXISTS)
							res.WriteHeader(http.StatusBadRequest)
							res.Write([]byte(STATUS_USR_ALREADY_EXISTS))
							return
						}
					}
					//Rehash the pw if needed
					if updatesToApply.Updates.Pw != "" {

						if err := userToUpdate.HashPassword(updatesToApply.Updates.Pw, a.Config.Salt); err != nil {
							log.Println(err)
							res.WriteHeader(http.StatusInternalServerError)
							res.Write([]byte(STATUS_ERR_UPDATING_USR))
							return
						}
					}
					//All good - now update
					if err := a.Store.UpsertUser(userToUpdate); err != nil {
						log.Println(err)
						res.WriteHeader(http.StatusInternalServerError)
						res.Write([]byte(STATUS_ERR_UPDATING_USR))
						return
					} else {
						res.WriteHeader(http.StatusOK)
						return
					}
				}
			}
		}
		res.WriteHeader(http.StatusBadRequest)
		res.Write([]byte(STATUS_NO_USR_DETAILS))
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
		res.WriteHeader(http.StatusForbidden)
		res.Write([]byte(STATUS_MISSING_ID_PW))
		return

	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) Login(res http.ResponseWriter, req *http.Request) {
	if usr, pw := unpackAuth(req.Header.Get("Authorization")); usr != nil {

		if results, err := a.Store.FindUsers(usr); err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(STATUS_ERR_FINDING_USR))
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
							log.Println(err)
							res.WriteHeader(http.StatusInternalServerError)
							res.Write([]byte(STATUS_ERR_UPDATING_TOKEN))
							return
						} else {
							res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
							sendModelAsRes(res, results[i])
							return
						}
					}
					res.WriteHeader(http.StatusUnauthorized)
					res.Write([]byte(STATUS_PW_WRONG))
					return
				}
			} else {
				res.WriteHeader(http.StatusNoContent)
				res.Write([]byte(STATUS_NO_MATCH))
				return
			}
		}
	}
	res.WriteHeader(http.StatusBadRequest)
	res.Write([]byte(STATUS_MISSING_ID_PW))
	return
}

func (a *Api) ServerLogin(res http.ResponseWriter, req *http.Request) {

	server, pw := req.Header.Get(TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)

	if server == "" || pw == "" {
		res.WriteHeader(http.StatusBadRequest)
		res.Write([]byte(STATUS_MISSING_ID_PW))
		return
	}
	if pw == a.Config.ServerSecret {
		//generate new token
		if sessionToken, err := a.createAndSaveToken(
			tokenDuration(req),
			server,
			true,
		); err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(STATUS_ERR_GENTERATING_TOKEN))
			return
		} else {
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
			res.WriteHeader(http.StatusOK)
			return
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	res.Write([]byte(STATUS_PW_WRONG))
	return
}

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
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(STATUS_ERR_GENTERATING_TOKEN))
			return
		} else {
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
			sendModelAsRes(res, td)
			return
		}

	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

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

func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if a.hasServerToken(req.Header.Get(TP_SESSION_TOKEN)) {
		tokenString := vars["token"]

		svrToken := &models.SessionToken{Id: tokenString}
		if td := svrToken.UnpackAndVerify(a.Config.Secret); td != nil && td.Valid {
			sendModelAsRes(res, td)
			return
		}
		res.WriteHeader(http.StatusNotFound)
		return
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	//lets just try and remove the token
	st := models.GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))
	if st.Id != "" {
		if err := a.Store.RemoveToken(st); err != nil {
			log.Println("Unable to delete token.", err)
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
