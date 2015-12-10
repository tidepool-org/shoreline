package user

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/tidepool-org/go-common/clients/highwater"
	"github.com/tidepool-org/go-common/clients/status"
	"github.com/tidepool-org/shoreline/common"
	"github.com/tidepool-org/shoreline/oauth2"
)

type (
	Api struct {
		Store     Storage
		ApiConfig ApiConfig
		metrics   highwater.Client
		oauth     oauth2.Client
		logger    *log.Logger
	}
	ApiConfig struct {
		//used for services
		ServerSecret         string `json:"serverSecret"`
		LongTermKey          string `json:"longTermKey"`
		LongTermDaysDuration int    `json:"longTermDaysDuration"`
		//so we can change the default lifetime of the token
		//we use seconds, this also helps for testing as you can time it out easily
		TokenDurationSecs float64 `json:"tokenDurationSecs"`
		//used for pw
		Salt string `json:"salt"`
		//used for token
		Secret string `json:"apiSecret"`
		//allows for the skipping of verification for testing
		VerificationSecret string `json:"verificationSecret"`
	}
	varsHandler func(http.ResponseWriter, *http.Request, map[string]string)
)

const (
	//api logging prefix
	USER_API_PREFIX = "api/user "

	TP_SERVER_NAME   = "x-tidepool-server-name"
	TP_SERVER_SECRET = "x-tidepool-server-secret"
	TP_SESSION_TOKEN = "x-tidepool-session-token"

	STATUS_NO_USR_DETAILS        = "No user details were given"
	STATUS_ERR_FINDING_USR       = "Error finding user"
	STATUS_ERR_CREATING_USR      = "Error creating the user"
	STATUS_ERR_UPDATING_USR      = "Error updating user"
	STATUS_USR_ALREADY_EXISTS    = "User already exists"
	STATUS_ERR_GENERATING_TOKEN  = "Error generating the token"
	STATUS_ERR_UPDATING_TOKEN    = "Error updating token"
	STATUS_MISSING_USR_DETAILS   = "Not all required details were given"
	STATUS_ERROR_UPDATING_PW     = "Error updating password"
	STATUS_MISSING_ID_PW         = "Missing id and/or password"
	STATUS_NO_MATCH              = "No user matched the given details"
	STATUS_NOT_VERIFIED          = "The user hasn't verified this account yet"
	STATUS_NO_TOKEN_MATCH        = "No token matched the given details"
	STATUS_PW_WRONG              = "Wrong password"
	STATUS_ERR_SENDING_EMAIL     = "Error sending email"
	STATUS_NO_TOKEN              = "No x-tidepool-session-token was found"
	STATUS_SERVER_TOKEN_REQUIRED = "A server token is required"
	STATUS_AUTH_HEADER_REQUIRED  = "Authorization header is required"
	STATUS_AUTH_HEADER_INVLAID   = "Authorization header is invalid"
	STATUS_GETSTATUS_ERR         = "Error checking service status"
)

func InitApi(cfg ApiConfig, store Storage, metrics highwater.Client) *Api {
	return &Api{
		Store:     store,
		ApiConfig: cfg,
		metrics:   metrics,
		logger:    log.New(os.Stdout, USER_API_PREFIX, log.Lshortfile),
	}
}

func (a *Api) AttachOauth(client oauth2.Client) {
	a.oauth = client
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

	rtr.HandleFunc("/oauthlogin", a.oauth2Login).Methods("POST")

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
		a.logger.Println(http.StatusInternalServerError, STATUS_GETSTATUS_ERR, err.Error())
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

	usrDetails, err := getUserDetail(req)

	if err != nil {
		a.logger.Println(http.StatusBadRequest, STATUS_MISSING_USR_DETAILS, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_USR_DETAILS), http.StatusBadRequest)
		return
	}

	newUsr, err := NewUser(usrDetails, a.ApiConfig.Salt)

	if err != nil {
		if err == User_error_name_pw_required {
			a.logger.Println(http.StatusBadRequest, STATUS_MISSING_USR_DETAILS, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_USR_DETAILS), http.StatusBadRequest)
			return
		} else {
			a.logger.Println(http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_CREATING_USR), http.StatusInternalServerError)
			return
		}
	}

	existingUsr, err := a.Store.FindUsers(newUsr)

	if err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_CREATING_USR), http.StatusInternalServerError)
		return
	}

	if existingUsr == nil || len(existingUsr) == 0 {
		//yay all is good!
		a.addUserAndSendStatus(newUsr, res, req)
		return
	}

	a.logger.Println(http.StatusConflict, STATUS_USR_ALREADY_EXISTS)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusConflict, STATUS_USR_ALREADY_EXISTS), http.StatusConflict)
	return
}

// status: 201 User
// status: 400 STATUS_MISSING_USR_DETAILS
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) CreateChildUser(res http.ResponseWriter, req *http.Request) {

	usrDetails, err := getUserDetail(req)

	if err != nil {
		a.logger.Println(http.StatusBadRequest, STATUS_MISSING_USR_DETAILS, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_USR_DETAILS), http.StatusBadRequest)
		return
	}

	newChildUsr, err := NewChildUser(usrDetails, a.ApiConfig.Salt)

	if err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_CREATING_USR), http.StatusInternalServerError)
		return
	}
	a.addUserAndSendStatus(newChildUsr, res, req)
	return
}

// status: 200
// status: 400 STATUS_NO_USR_DETAILS
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_FINDING_USR
// status: 500 STATUS_ERR_UPDATING_USR
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	td, err := getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret)

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	var (
		//structure that the update are given to us in
		updatesToApply struct {
			Updates *UserDetail `json:"updates"`
		}
	)

	usrId := vars["userid"]

	if usrId == "" && td.UserId == "" {
		//go no further
		a.logger.Println(http.StatusBadRequest, STATUS_NO_USR_DETAILS)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_NO_USR_DETAILS), http.StatusBadRequest)
		return
	} else if usrId == "" && td.UserId != "" {
		//use the id from the token
		usrId = td.UserId
	}

	if req.ContentLength > 0 {
		err := json.NewDecoder(req.Body).Decode(&updatesToApply)

		if err != nil {
			a.logger.Println(http.StatusInternalServerError, STATUS_NO_USR_DETAILS, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_NO_USR_DETAILS), http.StatusInternalServerError)
			return
		}
	}

	if updatesToApply.Updates != nil {

		//a.logger.Print("UpdateUser: applying updates ... ")
		usrToFind := UserFromDetails(&UserDetail{Id: usrId, Emails: []string{usrId}})

		if userToUpdate, err := a.Store.FindUser(usrToFind); err != nil {
			a.logger.Println(http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
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
					a.logger.Println(http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
					return
				} else if len(results) > 0 {
					a.logger.Println(http.StatusConflict, STATUS_USR_ALREADY_EXISTS)
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusConflict, STATUS_USR_ALREADY_EXISTS), http.StatusConflict)
					return
				}
			}
			//Rehash the pw if needed
			if updatesToApply.Updates.Pw != "" {

				if err := userToUpdate.HashPassword(updatesToApply.Updates.Pw, a.ApiConfig.Salt); err != nil {
					a.logger.Println(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err.Error())
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR), http.StatusInternalServerError)
					return
				}
			}

			//Updated TermsAccepted
			if updatesToApply.Updates.TermsAccepted != "" {
				userToUpdate.TermsAccepted = updatesToApply.Updates.TermsAccepted
			}

			//All good - now update
			if err := a.Store.UpsertUser(userToUpdate); err != nil {
				a.logger.Println(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err.Error())
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

//Pull the incoming user feilds to search for from http.Request body and
//find any matches returning them with return http.StatusOK
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	td, err := getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret)

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

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
		a.logger.Println(http.StatusBadRequest, STATUS_NO_USR_DETAILS)
		res.WriteHeader(http.StatusBadRequest)
		res.Write([]byte(STATUS_NO_USR_DETAILS))
		return
	} else {
		if results, err := a.Store.FindUsers(usr); err != nil {
			a.logger.Println(http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
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
				sendModelAsRes(res, results[0])
				return
			}

			a.logger.Printf(" found [%d] users ", len(results))
			sendModelsAsRes(res, results)
			return
		}
	}
}

func (a *Api) DeleteUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	td, err := getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret)

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	var id string
	if td.IsServer == true {
		id = vars["userid"]
		a.logger.Println("operating as server")
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
		a.logger.Println(http.StatusInternalServerError, err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		return
	}
	a.logger.Println(http.StatusForbidden, STATUS_MISSING_ID_PW)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusForbidden, STATUS_MISSING_ID_PW), http.StatusForbidden)
	return
}

// status: 200 TP_SESSION_TOKEN,
// status: 400 STATUS_MISSING_ID_PW
// status: 401 STATUS_NO_MATCH
// status: 403 STATUS_NOT_VERIFIED
// status: 500 STATUS_ERR_FINDING_USR, STATUS_ERR_UPDATING_TOKEN
func (a *Api) Login(res http.ResponseWriter, req *http.Request) {
	if usr, pw := unpackAuth(req.Header.Get("Authorization")); usr != nil {

		if results, err := a.Store.FindUsers(usr); results != nil && len(results) > 0 {
			for i := range results {
				if results[i].PwsMatch(pw, a.ApiConfig.Salt) && results[i].IsVerified(a.ApiConfig.VerificationSecret) {
					//passwords match and the user is verified
					td := &TokenData{DurationSecs: extractTokenDuration(req), UserId: results[i].Id, IsServer: false}

					if sessionToken, err := CreateSessionTokenAndSave(td, TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret}, a.Store); sessionToken != nil && err == nil {
						//YAY it's all is good so lets tell people!
						a.logMetric("userlogin", sessionToken.Id, nil)
						res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
						sendModelAsRes(res, results[i])
						return
					} else if err != nil {
						a.logger.Println(http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN, err.Error())
						sendModelAsResWithStatus(
							res,
							status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN),
							http.StatusInternalServerError,
						)
						return
					}
				} else {

					if results[i].PwsMatch(pw, a.ApiConfig.Salt) == false { //no password matches?
						a.logger.Println(http.StatusUnauthorized, STATUS_NO_MATCH)
						sendModelAsResWithStatus(
							res,
							status.NewStatus(http.StatusUnauthorized, STATUS_NO_MATCH),
							http.StatusUnauthorized,
						)
						return
					}

					if results[i].IsVerified(a.ApiConfig.VerificationSecret) == false { //not yet verified?
						a.logger.Println(http.StatusForbidden, STATUS_NOT_VERIFIED)
						sendModelAsResWithStatus(res, status.NewStatus(http.StatusForbidden, STATUS_NOT_VERIFIED), http.StatusForbidden)
						return
					}
				}
				//try next
				a.logger.Print("Login not valid for that user so checking the next")
			}
		} else {
			// was there an error?
			if err != nil {
				a.logger.Println(http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
				sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_FINDING_USR), http.StatusInternalServerError)
				return
			}
			//or just no user was found
			if results == nil || len(results) == 0 {
				a.logger.Println(http.StatusUnauthorized, STATUS_NO_MATCH)
				sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_MATCH), http.StatusUnauthorized)
				return
			}
		}
	}
	a.logger.Println(http.StatusBadRequest, STATUS_MISSING_ID_PW)
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
		a.logger.Println(http.StatusBadRequest, STATUS_MISSING_ID_PW)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_ID_PW), http.StatusBadRequest)
		return
	}
	if pw == a.ApiConfig.ServerSecret {
		//generate new token
		if sessionToken, err := CreateSessionTokenAndSave(
			&TokenData{DurationSecs: extractTokenDuration(req), UserId: server, IsServer: true},
			TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret},
			a.Store,
		); err != nil {
			a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
			return
		} else {
			a.logMetricAsServer("serverlogin", sessionToken.Id, nil)
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
			return
		}
	}
	a.logger.Println(http.StatusUnauthorized, STATUS_PW_WRONG)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
	return
}

// status: 200 TP_SESSION_TOKEN, oauthUser, oauthTarget
// status: 400 invalid_request
// status: 401 invalid_token
// status: 403 insufficient_scope
func (a *Api) oauth2Login(w http.ResponseWriter, r *http.Request) {

	//oauth is not enabled
	if a.oauth == nil {
		a.logger.Println(http.StatusServiceUnavailable, "OAuth is not enabled")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if ah := r.Header.Get("Authorization"); ah != "" {
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			if auth_token := ah[7:]; auth_token != "" {

				//check the actual token
				result, err := a.oauth.CheckToken(auth_token)
				if err != nil || result == nil {
					a.logger.Println(http.StatusUnauthorized, "oauth2Login error checking token ", err)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				//check the corresponding user
				fndUsr, errUsr := a.Store.FindUser(&User{Id: result["userId"].(string)})
				if errUsr != nil || fndUsr == nil {
					a.logger.Println(http.StatusUnauthorized, "oauth2Login error getting user ", errUsr.Error())
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				//generate token and send the response
				if sessionToken, err := CreateSessionTokenAndSave(
					&TokenData{DurationSecs: 0, UserId: result["userId"].(string), IsServer: false},
					TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret},
					a.Store,
				); err != nil {
					a.logger.Println(http.StatusUnauthorized, "oauth2Login error creating session token", err.Error())
					common.OutputJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "invalid_token"})
					return
				} else {
					//We are redirecting to the app
					w.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
					common.OutputJSON(w, http.StatusOK, map[string]interface{}{"oauthUser": fndUsr, "oauthTarget": result["authUserId"]})
					return
				}
			}
		}
		a.logger.Println(http.StatusUnauthorized, STATUS_AUTH_HEADER_INVLAID)
		common.OutputJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": STATUS_AUTH_HEADER_INVLAID})
		return
	}
	a.logger.Println(http.StatusBadRequest, STATUS_AUTH_HEADER_REQUIRED)
	common.OutputJSON(w, http.StatusBadRequest, map[string]interface{}{"error": STATUS_AUTH_HEADER_REQUIRED})
	return
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	td, err := getUnpackedToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret)

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	const two_hours_in_secs = 60 * 60 * 2

	if td.IsServer == false && td.DurationSecs > two_hours_in_secs {
		//long-duration let us know detail and keep it rolling
		a.logger.Println("long-duration token set for ", fmt.Sprint(time.Duration(td.DurationSecs)*time.Second))
	}
	//refresh
	if sessionToken, err := CreateSessionTokenAndSave(
		td,
		TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret},
		a.Store,
	); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else {
		res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
		sendModelAsRes(res, td)
		return
	}
}

// Set the longeterm duration and then process as per Login
// note: see Login for return codes
func (a *Api) LongtermLogin(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	const day_as_secs = 1 * 24 * 60 * 60

	duration := a.ApiConfig.LongTermDaysDuration * day_as_secs
	longtermkey := vars["longtermkey"]

	if longtermkey == a.ApiConfig.LongTermKey {
		a.logger.Println("token duration is ", fmt.Sprint(time.Duration(duration)*time.Second))
		req.Header.Add(TOKEN_DURATION_KEY, strconv.FormatFloat(float64(duration), 'f', -1, 64))
	} else {
		//tell us there was no match
		a.logger.Println("tried to login using the longtermkey but it didn't match the stored key")
	}

	a.Login(res, req)
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 404 STATUS_NO_TOKEN_MATCH
func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if hasServerToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret) {
		tokenString := vars["token"]

		svrToken := &SessionToken{Id: tokenString}
		td, err := svrToken.UnpackAndVerify(a.ApiConfig.Secret)
		if err != nil {
			a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
			return
		}

		if td.Valid {
			sendModelAsRes(res, td)
			return
		}
		a.logger.Println(http.StatusNotFound, STATUS_NO_TOKEN_MATCH)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusNotFound, STATUS_NO_TOKEN_MATCH), http.StatusNotFound)
		return
	}
	a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
	return
}

// status: 200
func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	//lets just try and remove the token
	st := GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))
	if st.Id != "" {
		if err := a.Store.RemoveToken(st); err != nil {
			//sliently fail but still log it
			a.logger.Println("Logout was unable to delete token", err.Error())
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
	if hasServerToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret) {

		usr := UserFromDetails(&UserDetail{Id: vars["userid"]})
		theKey := vars["key"]

		baseStrings := []string{a.ApiConfig.Salt, usr.Id, theKey}

		if foundUsr, err := a.Store.FindUser(usr); err != nil {
			a.logger.Println(http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
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
						a.logger.Println(http.StatusInternalServerError, req.Method, STATUS_ERR_UPDATING_USR, err.Error())
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
					a.logger.Printf("ManageIdHashPair %s %s [%s]", req.Method, STATUS_ERR_UPDATING_USR, err.Error())
					sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_UPDATING_USR), http.StatusInternalServerError)
					return
				} else {
					sendModelAsResWithStatus(res, foundUsr.Private[theKey], http.StatusCreated)
					return
				}
			case "DELETE":
				a.logger.Println(http.StatusNotImplemented, req.Method)
				res.WriteHeader(http.StatusNotImplemented)
				return
			}
			a.logger.Println(http.StatusBadRequest)
			res.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	a.logger.Println(http.StatusUnauthorized, STATUS_SERVER_TOKEN_REQUIRED)
	res.WriteHeader(http.StatusUnauthorized)
	return
}
