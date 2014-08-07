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
		ServerSecret string `json:"serverSecret"`
		LongTermKey  string `json:"longTermKey"`
		Salt         string `json:"salt"`
	}

	varsHandler func(http.ResponseWriter, *http.Request, map[string]string)
)

const (
	TP_SERVER_NAME    = "x-tidepool-server-name"
	TP_SERVER_SECRET  = "x-tidepool-server-secret"
	TP_SESSION_TOKEN  = "x-tidepool-session-token"
	TP_TOKEN_DURATION = "tokenduration"
)

func InitApi(store clients.StoreClient, cfg Config) *Api {
	return &Api{
		Store:  store,
		Config: cfg,
	}
}

func (a *Api) SetHandlers(prefix string, rtr *mux.Router) {

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
func getToken(req *http.Request) (st *models.SessionToken) {
	st = models.GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))
	if st.Token == "" {
		return nil
	}
	return st
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
func unpackAuth(authLine string) (usr *models.User) {
	if authLine != "" {
		parts := strings.SplitN(authLine, " ", 2)
		payload := parts[1]
		if decodedPayload, err := base64.URLEncoding.DecodeString(payload); err != nil {
			log.Print(err)
		} else {
			details := strings.Split(string(decodedPayload), ":")
			if details[0] != "" || details[1] != "" {
				//Note the incoming `name` coule infact be id, email or the username
				return models.UserFromDetails(&models.UserDetail{Id: details[0], Name: details[0], Emails: []string{details[0]}, Pw: details[1]})
			}
		}
	}
	return nil
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

func (a *Api) hasServerToken(req *http.Request) bool {

	if svrToken := getToken(req); svrToken != nil {
		if ok := svrToken.UnpackAndVerify(a.Config.ServerSecret); ok == true {
			return svrToken.TokenData.IsServer
		}
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
		a.Config.ServerSecret,
	)

	if err := a.Store.AddToken(sessionToken); err == nil {
		return sessionToken, nil
	} else {
		return nil, err
	}
}

//Pull the incoming user from the http.Request body and save return http.StatusCreated
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if usrDetails := getUserDetail(req); usrDetails != nil {
		if usr, err := models.NewUser(usrDetails, a.Config.Salt); err == nil {
			if err := a.Store.UpsertUser(usr); err != nil {
				log.Println(err)
				res.WriteHeader(http.StatusInternalServerError)
				return
			}
			if sessionToken, err := a.createAndSaveToken(tokenDuration(req), usr.Id, false); err != nil {
				log.Println(err)
				res.WriteHeader(http.StatusInternalServerError)
				return
			} else {
				res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
				sendModelAsResWithStatus(res, usr, http.StatusCreated)
				return
			}

		} else {
			log.Println(err)
		}
	}
	//incoming details were bad
	res.WriteHeader(http.StatusBadRequest)
	return
}

//Pull the incoming user updates from http.Request body and save return http.StatusOK
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if sessionToken := getToken(req); sessionToken != nil {

		id := vars["userid"]

		if updatesToApply := getUserDetail(req); updatesToApply != nil && id != "" {

			usrToFind := models.UserFromDetails(&models.UserDetail{Id: id, Emails: []string{id}})

			if userToUpdate, err := a.Store.FindUser(usrToFind); err != nil {
				log.Println(err)
				res.WriteHeader(http.StatusInternalServerError)
				return
			} else if userToUpdate != nil {

				//Name and/or Emails and perform dups check
				if updatesToApply.Name != "" || len(updatesToApply.Emails) > 0 {
					dupCheck := models.UserFromDetails(&models.UserDetail{})
					if updatesToApply.Name != "" {
						userToUpdate.Name = updatesToApply.Name
						dupCheck.Name = userToUpdate.Name
					}
					if len(updatesToApply.Emails) > 0 {
						userToUpdate.Emails = updatesToApply.Emails
						dupCheck.Emails = userToUpdate.Emails
					}
					//check if unique
					if results, err := a.Store.FindUsers(dupCheck); err != nil {
						log.Println(err)
						res.WriteHeader(http.StatusInternalServerError)
						return
					} else if len(results) > 0 {
						log.Println("Users found with this name and/or email already ")
						res.WriteHeader(http.StatusBadRequest)
						return
					}
				}
				//Rehash the pw if needed
				if updatesToApply.Pw != "" {

					if err := userToUpdate.HashPassword(updatesToApply.Pw, a.Config.Salt); err != nil {
						log.Println(err)
						res.WriteHeader(http.StatusInternalServerError)
						return
					}
				}
				//All good - now update
				if err := a.Store.UpsertUser(userToUpdate); err != nil {
					log.Println(err)
					res.WriteHeader(http.StatusInternalServerError)
					return
				} else {
					res.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		res.WriteHeader(http.StatusBadRequest)
		return
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

//Pull the incoming user feilds to search for from http.Request body and
//find any matches returning them with return http.StatusOK
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if sessionToken := getToken(req); sessionToken != nil {

		var usr *models.User

		id := vars["userid"]
		if id != "" {
			//the `userid` could infact be an email
			usr = models.UserFromDetails(&models.UserDetail{Id: id, Emails: []string{id}})
		} else {
			//use the token to find the userid
			if sessionToken.UnpackAndVerify(a.Config.ServerSecret) {
				usr = models.UserFromDetails(&models.UserDetail{Id: sessionToken.TokenData.UserId})
			}
		}

		if usr == nil {
			res.WriteHeader(http.StatusBadRequest)
			return
		} else {
			if results, err := a.Store.FindUsers(usr); err != nil {
				log.Println(err)
				res.WriteHeader(http.StatusInternalServerError)
				return
			} else if results != nil {
				if len(results) == 1 && usr.Pw != "" {
					if results[0].PwsMatch(usr, a.Config.Salt) {
						sendModelAsRes(res, results[0])
						return
					} else {
						res.WriteHeader(http.StatusNoContent)
						return
					}
				} else if len(results) == 1 {
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

	if sessionToken := getToken(req); sessionToken != nil {

		if sessionToken.UnpackAndVerify(a.Config.ServerSecret) {
			var id string
			if sessionToken.TokenData.IsServer == true {
				id = vars["userid"]
			} else {
				id = sessionToken.TokenData.UserId
			}
			details := getGivenDetail(req)
			pw := details["password"]

			if id != "" && pw != "" {

				var err error
				toDelete := models.UserFromDetails(&models.UserDetail{Id: id})

				if err = toDelete.HashPassword(pw, a.Config.Salt); err == nil {
					if err = a.Store.RemoveUser(toDelete); err == nil {
						//cleanup if any
						if sessionToken.TokenData.IsServer == false {
							a.Store.RemoveToken(sessionToken)
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
			return
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) Login(res http.ResponseWriter, req *http.Request) {

	if usr := unpackAuth(req.Header.Get("Authorization")); usr != nil {

		if results, err := a.Store.FindUsers(usr); err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			for i := range results {
				//ensure a pw match
				if results[i].PwsMatch(usr, a.Config.Salt) {
					//a mactch so login
					if sessionToken, err := a.createAndSaveToken(
						tokenDuration(req),
						results[i].Id,
						false,
					); err != nil {
						log.Println(err)
						res.WriteHeader(http.StatusInternalServerError)
						return
					} else {
						res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
						sendModelAsRes(res, results[i])
						return
					}
				} else {
					res.WriteHeader(http.StatusUnauthorized)
					return
				}

			}
		}
	}
	res.WriteHeader(http.StatusBadRequest)
	return
}

func (a *Api) ServerLogin(res http.ResponseWriter, req *http.Request) {

	server, pw := req.Header.Get(TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)

	if server == "" || pw == "" {
		res.WriteHeader(http.StatusBadRequest)
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
			return
		} else {
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
			res.WriteHeader(http.StatusOK)
			return
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	if sessionToken := getToken(req); sessionToken != nil {
		const TWO_HOURS_IN_SECS = 60 * 60 * 2

		if sessionToken.UnpackAndVerify(a.Config.ServerSecret) {

			if sessionToken.TokenData.IsServer == false && sessionToken.TokenData.DurationSecs > TWO_HOURS_IN_SECS {
				//long-duration, it's not renewable, so just return it
				sendModelAsRes(res, sessionToken.TokenData.UserId)
				return
			}
			//refresh
			if sessionToken, err := a.createAndSaveToken(
				tokenDuration(req),
				sessionToken.TokenData.UserId,
				sessionToken.TokenData.IsServer,
			); err != nil {
				log.Println(err)
				res.WriteHeader(http.StatusInternalServerError)
				return
			} else {
				res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
				res.WriteHeader(http.StatusOK)
				return
			}
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

	if a.hasServerToken(req) {
		tokenString := vars["token"]

		svrToken := &models.SessionToken{Token: tokenString}
		if ok := svrToken.UnpackAndVerify(a.Config.ServerSecret); ok == true {
			sendModelAsRes(res, svrToken.TokenData)
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
	if sessionToken := getToken(req); sessionToken != nil {

		if err := a.Store.RemoveToken(sessionToken); err != nil {
			log.Println("Unable to delete token.", err)
		}

	}
	//otherwise all good
	res.WriteHeader(http.StatusOK)
	return
}

func (a *Api) AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	if len(req.URL.Query()) > 0 {
		idHashPair := models.NewAnonIdHashPair([]string{a.Config.Salt}, req.URL.Query())
		sendModelAsRes(res, idHashPair)
		return
	}
	res.WriteHeader(http.StatusBadRequest)
	return
}

func (a *Api) ManageIdHashPair(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	//we need server token
	if a.hasServerToken(req) {

		usr := models.UserFromDetails(&models.UserDetail{Id: vars["userid"]})
		theKey := vars["key"]

		baseStrings := []string{a.Config.Salt, usr.Id, theKey}

		if foundUsr, err := a.Store.FindUser(usr); err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
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
