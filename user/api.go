package user

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common/clients/highwater"
	"github.com/tidepool-org/go-common/clients/status"
)

type (
	Api struct {
		Store     Storage
		ApiConfig ApiConfig
		metrics   highwater.Client
	}
	ApiConfig struct {
		ServerSecret         string `json:"serverSecret"` //used for services
		LongTermKey          string `json:"longTermKey"`
		LongTermDaysDuration int    `json:"longTermDaysDuration"`
		Salt                 string `json:"salt"`               //used for pw
		Secret               string `json:"apiSecret"`          //used for token
		VerificationSecret   string `json:"verificationSecret"` //allows for the skipping of verification for testing
	}
	varsHandler func(http.ResponseWriter, *http.Request, map[string]string)
)

const (
	//api logging prefix
	USER_API_PREFIX = "api/user "

	TP_SERVER_NAME              = "x-tidepool-server-name"
	TP_SERVER_SECRET            = "x-tidepool-server-secret"
	TP_SESSION_TOKEN            = "x-tidepool-session-token"
	STATUS_NO_USR_DETAILS       = "No user details were given"
	STATUS_ERR_FINDING_USR      = "Error finding user"
	STATUS_ERR_CREATING_USR     = "Error creating the user"
	STATUS_ERR_UPDATING_USR     = "Error updating user"
	STATUS_USR_ALREADY_EXISTS   = "User aleady exists"
	STATUS_ERR_GENERATING_TOKEN = "Error generating the token"
	STATUS_ERR_UPDATING_TOKEN   = "Error updating token"
	STATUS_MISSING_USR_DETAILS  = "Not all required details were given"
	STATUS_ERROR_UPDATING_PW    = "Error updating password"
	STATUS_MISSING_ID_PW        = "Missing id and/or password"
	STATUS_NO_MATCH             = "No user matched the given details"
	STATUS_NOT_VERIFIED         = "The user hasn't verified this account yet"
	STATUS_NO_TOKEN_MATCH       = "No token matched the given details"
	STATUS_PW_WRONG             = "Wrong password"
	STATUS_ERR_SENDING_EMAIL    = "Error sending email"
	STATUS_NO_TOKEN             = "No x-tidepool-session-token was found"
)

func InitApi(cfg ApiConfig, store Storage, metrics highwater.Client) *Api {
	return &Api{
		Store:     store,
		ApiConfig: cfg,
		metrics:   metrics,
	}
}

func (a *Api) SetHandlers(prefix string, rtr *mux.Router) {

	rtr.HandleFunc("/status", a.GetStatus).Methods("GET")

	rtr.Handle("/user", varsHandler(a.GetUserInfo)).Methods("GET")
	rtr.Handle("/user/{userid}", varsHandler(a.GetUserInfo)).Methods("GET")

	rtr.HandleFunc("/childuser", a.CreateChildUser).Methods("POST")

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

func (a *Api) GetStatus(res http.ResponseWriter, req *http.Request) {
	if err := a.Store.Ping(); err != nil {
		log.Print(USER_API_PREFIX, err)
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
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if usrDetails := getUserDetail(req); usrDetails != nil {

		if usr, err := NewUser(usrDetails, a.ApiConfig.Salt); err == nil {
			//they shouldn't already exist
			if results, _ := a.Store.FindUsers(usr); results == nil || len(results) == 0 {
				log.Printf(USER_API_PREFIX+"CreateUser adding [%v] ", usr)
				a.addUserAndSendStatus(usr, res, req)
				return
			} else {
				log.Printf(USER_API_PREFIX+"CreateUser %s ", STATUS_USR_ALREADY_EXISTS)
				sendModelAsResWithStatus(res, status.NewStatus(http.StatusConflict, STATUS_USR_ALREADY_EXISTS), http.StatusConflict)
				return
			}
		} else {
			log.Printf(USER_API_PREFIX+"CreateUser %s ", err.Error())
		}
	}
	//incoming details missing
	log.Printf(USER_API_PREFIX+"CreateUser %s ", STATUS_MISSING_USR_DETAILS)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_USR_DETAILS), http.StatusBadRequest)
	return
}

// status: 201 User
// status: 400 STATUS_MISSING_USR_DETAILS
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) CreateChildUser(res http.ResponseWriter, req *http.Request) {

	if usrDetails := getUserDetail(req); usrDetails != nil {

		if usr, err := NewChildUser(usrDetails, a.ApiConfig.Salt); err == nil {
			log.Printf(USER_API_PREFIX+"CreateChildUser adding [%v] ", usr)
			a.addUserAndSendStatus(usr, res, req)
			return
		} else {
			log.Printf(USER_API_PREFIX+"CreateChildUser %s ", err.Error())
		}
	}
	//incoming details were missing
	log.Printf(USER_API_PREFIX+"CreateChildUser %s ", STATUS_MISSING_USR_DETAILS)
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
			//structure that the update are given to us in
			updatesToApply struct {
				Updates *UserDetail `json:"updates"`
			}
		)

		usrId := vars["userid"]

		if usrId == "" && td.UserId == "" {
			//go no further
			log.Printf(USER_API_PREFIX+"UpdateUser id [%s] token id [%s] ", usrId, td.UserId)
			log.Printf(USER_API_PREFIX+"UpdateUser %s ", STATUS_NO_USR_DETAILS)
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_NO_USR_DETAILS), http.StatusBadRequest)
			return
		} else if usrId == "" && td.UserId != "" {
			//use the id from the token
			usrId = td.UserId
		}

		if req.ContentLength > 0 {
			_ = json.NewDecoder(req.Body).Decode(&updatesToApply)
		}

		if updatesToApply.Updates != nil {

			log.Printf(USER_API_PREFIX+"UpdateUser: applying updates ... [%v]", updatesToApply.Updates)

			usrToFind := UserFromDetails(&UserDetail{Id: usrId, Emails: []string{usrId}})

			log.Printf(USER_API_PREFIX+"UpdateUser: updating ... [%v]", usrToFind)

			if userToUpdate, err := a.Store.FindUser(usrToFind); err != nil {
				log.Printf(USER_API_PREFIX+"UpdateUser %s err[%s]", STATUS_ERR_FINDING_USR, err.Error())
				sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
				return
			} else if userToUpdate != nil {

				//Verifiy the user
				if userToUpdate.Verified == false && updatesToApply.Updates.Verified {
					userToUpdate.Verified = updatesToApply.Updates.Verified
				}

				//Name and/or Emails and perform dups check
				if updatesToApply.Updates.Name != "" || len(updatesToApply.Updates.Emails) > 0 {
					dupCheck := UserFromDetails(&UserDetail{})
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
						log.Printf(USER_API_PREFIX+"UpdateUser %s err[%s]", STATUS_ERR_FINDING_USR, err.Error())
						sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
						return
					} else if len(results) > 0 {
						log.Printf(USER_API_PREFIX+"UpdateUser %s ", STATUS_USR_ALREADY_EXISTS)
						sendModelAsResWithStatus(res, status.NewStatus(http.StatusConflict, STATUS_USR_ALREADY_EXISTS), http.StatusConflict)
						return
					}
				}
				//Rehash the pw if needed
				if updatesToApply.Updates.Pw != "" {

					if err := userToUpdate.HashPassword(updatesToApply.Updates.Pw, a.ApiConfig.Salt); err != nil {
						log.Printf(USER_API_PREFIX+"UpdateUser %s err[%s]", STATUS_ERR_UPDATING_USR, err.Error())
						sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR), http.StatusInternalServerError)
						return
					}
				}

				//All good - now update
				if err := a.Store.UpsertUser(userToUpdate); err != nil {
					log.Printf(USER_API_PREFIX+"UpdateUser %s err[%s]", STATUS_ERR_UPDATING_USR, err.Error())
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR), http.StatusInternalServerError)
					return
				} else {
					if td.IsServer {
						a.logMetricForUser(usrId, "userupdated", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "true"})
					} else {
						a.logMetric("userupdated", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "false"})
					}
					res.WriteHeader(http.StatusOK)
					return
				}
			}
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

//Pull the incoming user feilds to search for from http.Request body and
//find any matches returning them with return http.StatusOK
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if td := a.getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN)); td != nil {

		var usr *User

		id := vars["userid"]
		if id != "" {
			//the `userid` could infact be an email
			usr = UserFromDetails(&UserDetail{Id: id, Emails: []string{id}})
		} else {
			//use the token to find the userid
			usr = UserFromDetails(&UserDetail{Id: td.UserId})
		}

		if usr == nil {
			res.WriteHeader(http.StatusBadRequest)
			res.Write([]byte(STATUS_NO_USR_DETAILS))
			return
		} else {
			if results, err := a.Store.FindUsers(usr); err != nil {
				log.Print(USER_API_PREFIX, err)
				res.WriteHeader(http.StatusInternalServerError)
				res.Write([]byte(STATUS_ERR_FINDING_USR))
				return
			} else if results != nil {

				if td.IsServer {
					a.logMetricForUser(id, "getuserinfo", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "true"})
				} else {
					a.logMetric("getuserinfo", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "false"})
				}

				if len(results) == 1 {
					log.Printf(USER_API_PREFIX+"found user [%v]", results[0])
					sendModelAsRes(res, results[0])
					return
				}

				log.Printf(USER_API_PREFIX+"found users [%v]", results)
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
			toDelete := UserFromDetails(&UserDetail{Id: id})

			if err = toDelete.HashPassword(pw, a.ApiConfig.Salt); err == nil {
				if err = a.Store.RemoveUser(toDelete); err == nil {

					if td.IsServer {
						a.logMetricForUser(id, "deleteuser", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "true"})
					} else {
						a.logMetric("deleteuser", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "false"})
					}

					//cleanup if any
					if td.IsServer == false {
						usrToken := &SessionToken{Id: req.Header.Get(TP_SESSION_TOKEN)}
						a.Store.RemoveToken(usrToken)
					}
					//all good
					res.WriteHeader(http.StatusAccepted)
					return
				}
			}
			log.Print(USER_API_PREFIX, err)
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
// status: 400 STATUS_MISSING_ID_PW
// status: 401 STATUS_NO_MATCH
// status: 403 STATUS_NOT_VERIFIED
// status: 500 STATUS_ERR_FINDING_USR
// status: 500 STATUS_ERR_UPDATING_TOKEN
func (a *Api) Login(res http.ResponseWriter, req *http.Request) {
	if usr, pw := unpackAuth(req.Header.Get("Authorization")); usr != nil {

		if results, err := a.Store.FindUsers(usr); err != nil {
			log.Printf(USER_API_PREFIX+"Login %s [%s]", STATUS_ERR_FINDING_USR, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
			return
		} else {
			if len(results) > 0 {
				for i := range results {
					if results[i] != nil && results[i].PwsMatch(pw, a.ApiConfig.Salt) {

						if results[i].IsVerified(a.ApiConfig.VerificationSecret) {

							if sessionToken, err := a.createAndSaveToken(tokenDuration(req), results[i].Id, false); err != nil {
								log.Printf(USER_API_PREFIX+"Login %s [%s]", STATUS_ERR_UPDATING_TOKEN, err.Error())
								sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN), http.StatusInternalServerError)
								return
							} else {
								a.logMetric("userlogin", sessionToken.Id, nil)
								res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
								sendModelAsRes(res, results[i])
								return
							}
						}
						log.Printf(USER_API_PREFIX+"Login %s for [%s]", STATUS_NOT_VERIFIED, usr.Id)
						sendModelAsResWithStatus(res, status.NewStatus(http.StatusForbidden, STATUS_NOT_VERIFIED), http.StatusForbidden)
						return
					}
					log.Printf(USER_API_PREFIX+"Login %s [%s] from the [%d] users we found", STATUS_NO_MATCH, usr.Name, len(results))
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_MATCH), http.StatusUnauthorized)
					return
				}
			}
			log.Printf(USER_API_PREFIX+"Login %s for [%s]", STATUS_NO_MATCH, usr.Name)
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_MATCH), http.StatusUnauthorized)
			return
		}
	}
	log.Printf(USER_API_PREFIX+"Login %s ", STATUS_MISSING_ID_PW)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_ID_PW), http.StatusBadRequest)
	return
}

// status: 200 TP_SESSION_TOKEN
// status: 400 STATUS_MISSING_ID_PW
// status: 401 STATUS_PW_WRONG
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) ServerLogin(res http.ResponseWriter, req *http.Request) {

	server, pw := req.Header.Get(TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)

	if server == "" || pw == "" {
		log.Print(USER_API_PREFIX, "ServerLogin "+STATUS_MISSING_ID_PW)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_ID_PW), http.StatusBadRequest)
		return
	}
	if pw == a.ApiConfig.ServerSecret {
		//generate new token
		if sessionToken, err := a.createAndSaveToken(
			tokenDuration(req),
			server,
			true,
		); err != nil {
			log.Printf(USER_API_PREFIX+"ServerLogin %s err[%s]", STATUS_ERR_GENERATING_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
			return
		} else {
			a.logMetricAsServer("serverlogin", sessionToken.Id, nil)
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
			return
		}
	}
	log.Printf(USER_API_PREFIX+"ServerLogin %s ", STATUS_PW_WRONG)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
	return
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	if td := a.getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN)); td != nil {
		const TWO_HOURS_IN_SECS = 60 * 60 * 2

		if td.IsServer == false && td.DurationSecs > TWO_HOURS_IN_SECS {
			//long-duration let us know detail and keep it rolling
			log.Printf(USER_API_PREFIX+"RefreshSession this is a long-duration token set for [%f] ", td.DurationSecs)
		}
		//refresh
		if sessionToken, err := a.createAndSaveToken(
			td.DurationSecs,
			td.UserId,
			td.IsServer,
		); err != nil {
			log.Printf(USER_API_PREFIX+"RefreshSession %s err[%s]", STATUS_ERR_GENERATING_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
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
		DAY_AS_SECS = 1 * 24 * 60 * 60
	)
	log.Print(USER_API_PREFIX, "LongtermLogin: logging in using the longtermkey")
	duration := a.ApiConfig.LongTermDaysDuration * DAY_AS_SECS
	longtermkey := vars["longtermkey"]

	if longtermkey == a.ApiConfig.LongTermKey {
		log.Printf(USER_API_PREFIX+"LongtermLogin: setting the duration of the token as [%d] ", duration)
		req.Header.Add(TP_TOKEN_DURATION, strconv.FormatFloat(float64(duration), 'f', -1, 64))
	} else {
		//tell us there was no match
		log.Printf(USER_API_PREFIX+"LongtermLogin: tried to login using the longtermkey [%s] but it didn't match the stored key ", longtermkey)
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

		svrToken := &SessionToken{Id: tokenString}
		if td := svrToken.UnpackAndVerify(a.ApiConfig.Secret); td != nil && td.Valid {
			sendModelAsRes(res, td)
			return
		}
		log.Printf(USER_API_PREFIX+"ServerCheckToken %s", STATUS_NO_TOKEN_MATCH)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusNotFound, STATUS_NO_TOKEN_MATCH), http.StatusNotFound)
		return
	}
	log.Printf(USER_API_PREFIX+"ServerCheckToken %s", STATUS_NO_TOKEN)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
	return
}

// status: 200
func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	//lets just try and remove the token
	st := GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))
	if st.Id != "" {
		if err := a.Store.RemoveToken(st); err != nil {
			log.Printf(USER_API_PREFIX+"Logout was unable to delete token err[%s]", err.Error())
		}
	}
	//otherwise all good
	res.WriteHeader(http.StatusOK)
	return
}

// status: 200 AnonIdHashPair
func (a *Api) AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	idHashPair := NewAnonIdHashPair([]string{a.ApiConfig.Salt}, req.URL.Query())
	sendModelAsRes(res, idHashPair)
	return
}

// status: 200 IdHashPair
// status: 500 STATUS_ERR_FINDING_USR
// status: 500 STATUS_ERR_UPDATING_USR
func (a *Api) ManageIdHashPair(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	//we need server token
	if a.hasServerToken(req.Header.Get(TP_SESSION_TOKEN)) {

		usr := UserFromDetails(&UserDetail{Id: vars["userid"]})
		theKey := vars["key"]

		baseStrings := []string{a.ApiConfig.Salt, usr.Id, theKey}

		if foundUsr, err := a.Store.FindUser(usr); err != nil {
			log.Printf(USER_API_PREFIX+"ManageIdHashPair %s [%s]", STATUS_ERR_FINDING_USR, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
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
						foundUsr.Private = make(map[string]*IdHashPair)
					}
					foundUsr.Private[theKey] = NewIdHashPair(baseStrings, req.URL.Query())

					if err := a.Store.UpsertUser(foundUsr); err != nil {
						log.Printf(USER_API_PREFIX+"ManageIdHashPair %s %s [%s]", req.Method, STATUS_ERR_UPDATING_USR, err.Error())
						sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR), http.StatusInternalServerError)
						return
					} else {
						sendModelAsRes(res, foundUsr.Private[theKey])
						return
					}
				}
			case "POST", "PUT":
				if foundUsr.Private == nil {
					foundUsr.Private = make(map[string]*IdHashPair)
				}
				foundUsr.Private[theKey] = NewIdHashPair(baseStrings, req.URL.Query())

				if err := a.Store.UpsertUser(foundUsr); err != nil {
					log.Printf(USER_API_PREFIX+"ManageIdHashPair %s %s [%s]", req.Method, STATUS_ERR_UPDATING_USR, err.Error())
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR), http.StatusInternalServerError)
					return
				} else {
					sendModelAsResWithStatus(res, foundUsr.Private[theKey], http.StatusCreated)
					return
				}
			case "DELETE":
				log.Printf(USER_API_PREFIX+"ManageIdHashPair %s %s", req.Method, "Not Implemented")
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
