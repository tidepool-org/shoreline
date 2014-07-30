package api

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/tidepool-org/shoreline/clients"
	"github.com/tidepool-org/shoreline/models"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type (
	Api struct {
		Store  clients.StoreClient
		rtr    *mux.Router
		Config Config
	}
	Config struct {
		ServerSecret string
		LongTermKey  string
		Salt         string
	}

	varsHandler func(http.ResponseWriter, *http.Request, map[string]string)
)

const (
	TP_SERVER_NAME    = "x-tidepool-server-name"
	TP_SERVER_SECRET  = "x-tidepool-server-secret"
	TP_SESSION_TOKEN  = "x-tidepool-session-token"
	TP_TOKEN_DURATION = "tokenduration"
)

func InitApi(store clients.StoreClient, cfg Config, rtr *mux.Router) *Api {
	return &Api{
		Store:  store,
		rtr:    rtr,
		Config: cfg,
	}
}

func (a *Api) SetHandlers() {
	if a.rtr == nil {
		return
	}
	a.rtr.Handle("/user", varsHandler(a.GetUserInfo)).Methods("GET")
	a.rtr.Handle("/user/{userid}", varsHandler(a.GetUserInfo)).Methods("GET")

	a.rtr.HandleFunc("/user", a.CreateUser).Methods("POST")
	a.rtr.Handle("/user", varsHandler(a.UpdateUser)).Methods("PUT")
	a.rtr.Handle("/user/{userid}", varsHandler(a.UpdateUser)).Methods("PUT")

	a.rtr.HandleFunc("/login", a.Login).Methods("POST")
	a.rtr.HandleFunc("/login", a.RefreshSession).Methods("GET")
	a.rtr.Handle("/login/{longtermkey}", varsHandler(a.LongtermLogin)).Methods("POST")

	a.rtr.HandleFunc("/serverlogin", a.ServerLogin).Methods("POST")

	a.rtr.Handle("/token/{token}", varsHandler(a.ServerCheckToken)).Methods("GET")

	a.rtr.HandleFunc("/logout", a.Logout).Methods("POST")

	a.rtr.HandleFunc("/private", a.AnonymousIdHashPair).Methods("GET")
	a.rtr.Handle("/private/{userid}/{key}", varsHandler(a.ManageIdHashPair)).Methods("GET", "POST", "PUT", "DELETE")
}

func (h varsHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	h(res, req, vars)
}

//Docode the http.Request parsing out the user model
func findUserDetail(res http.ResponseWriter, req *http.Request) (usr *models.User) {

	id := mux.Vars(req)["userid"]

	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&usr); err != nil {
			log.Println("error trying to decode user detail ", err)
			return nil
		}
	}

	if usr != nil && id != "" {
		usr.Id = id
	} else if id != "" {
		usr = &models.User{Id: id}
	}

	return usr
}

//Check token and return http.StatusUnauthorized if not found
func tokenCheck(res http.ResponseWriter, req *http.Request) {
	token := models.GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))
	if token.Token == "" {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
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
				return &models.User{Name: details[0], Pw: details[1]}
			}
		}
	}
	return nil
}

func sendModelsAsRes(res http.ResponseWriter, models ...interface{}) {

	res.WriteHeader(http.StatusOK)
	res.Header().Add("content-type", "application/json")

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
}

func sendModelAsResWithStatus(res http.ResponseWriter, model interface{}, statusCode int) {
	res.WriteHeader(statusCode)
	res.Header().Add("content-type", "application/json")

	if jsonDetails, err := json.Marshal(model); err != nil {
		log.Println(err)
	} else {
		res.Write(jsonDetails)
	}
	return
}

func (a *Api) requireServerToken(res http.ResponseWriter, req *http.Request) {
	tokenCheck(res, req)

	svrToken := models.GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))

	if ok := svrToken.Verify(a.Config.ServerSecret); ok == true {
		if svrToken.TokenData.IsServer {
			return
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
}

//Pull the incoming user from the http.Request body and save return http.StatusCreated
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if usr := findUserDetail(res, req); usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		if err := a.Store.UpsertUser(usr); err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			return
		}

		res.WriteHeader(http.StatusCreated)
		return
	}
}

//Pull the incoming user updates from http.Request body and save return http.StatusOK
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	tokenCheck(res, req)

	if usr := findUserDetail(res, req); usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		if err := a.Store.UpsertUser(usr); err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			return
		}

		res.WriteHeader(http.StatusOK)
		return
	}
}

//Pull the incoming user feilds to search for from http.Request body and
//find any matches returning them with return http.StatusOK
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	tokenCheck(res, req)

	var usr *models.User

	//TODO: could be id or email infact
	id := vars["userid"]
	if id != "" {
		usr = &models.User{Id: id}
	} else {
		//use the token to find the userid
		token := models.GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))
		token.Verify(a.Config.ServerSecret)
		usr = &models.User{Id: token.TokenData.UserId}
	}

	if usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {
		if results, err := a.Store.FindUsers(usr); err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			if len(results) == 1 && usr.Pw != "" {
				if results[0].HasPwMatch(usr, a.Config.Salt) {
					sendModelAsRes(res, results[0])
				}
				res.WriteHeader(http.StatusNoContent)
				return
			} else if len(results) == 1 {
				sendModelAsRes(res, results[0])
			}
			sendModelsAsRes(res, results)
		}
	}
}

func (a *Api) DeleteUser(res http.ResponseWriter, req *http.Request) {

	tokenCheck(res, req)
	//TODO:
	res.WriteHeader(501)
}

func (a *Api) Login(res http.ResponseWriter, req *http.Request) {

	if usr := unpackAuth(req.Header.Get("Authorization")); usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {
		if results, err := a.Store.FindUsers(usr); results != nil {
			for i := range results {
				//ensure a pw match
				if results[i].HasPwMatch(usr, a.Config.Salt) {

					sessionToken, _ := models.NewSessionToken(
						&models.TokenData{
							UserId:   results[i].Id,
							IsServer: false,
							Duration: tokenDuration(req),
						},
						a.Config.ServerSecret,
					)

					if err := a.Store.AddToken(sessionToken); err == nil {
						res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
						//postThisUser('userlogin', {}, sessiontoken);
						sendModelAsRes(res, results[0])
						return
					} else {
						log.Println(err)
						res.WriteHeader(http.StatusInternalServerError)
						return
					}
				}
			}
		} else if err != nil {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	//default
	res.WriteHeader(http.StatusUnauthorized)
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

		sessionToken, _ := models.NewSessionToken(
			&models.TokenData{
				UserId:   server,
				IsServer: true,
				Duration: tokenDuration(req),
			},
			a.Config.ServerSecret,
		)

		if err := a.Store.AddToken(sessionToken); err == nil {
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
			res.WriteHeader(http.StatusOK)
			//postServer('serverlogin', {}, sessiontoken);
			return
		} else {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	const (
		TWO_HOURS_IN_SECS = 60 * 60 * 2
	)

	sessionToken := models.GetSessionToken(req.Header.Get(TP_SESSION_TOKEN))

	if ok := sessionToken.Verify(a.Config.ServerSecret); ok == true {

		if sessionToken.TokenData.IsServer == false && sessionToken.TokenData.Duration > TWO_HOURS_IN_SECS {
			//long-duration, it's not renewable, so just return it
			sendModelAsRes(res, sessionToken.TokenData.UserId)
		}

		newToken, _ := models.NewSessionToken(
			&models.TokenData{
				UserId:   sessionToken.TokenData.UserId,
				Duration: tokenDuration(req),
				IsServer: sessionToken.TokenData.IsServer,
			},
			a.Config.ServerSecret,
		)

		if err := a.Store.AddToken(newToken); err == nil {
			res.Header().Set(TP_SESSION_TOKEN, newToken.Token)
			res.WriteHeader(http.StatusOK)
			//postServer('serverlogin', {}, sessiontoken);
			return
		} else {
			log.Println(err)
			res.WriteHeader(http.StatusInternalServerError)
			return
		}

	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) LongtermLogin(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	longtermkey := vars["longtermkey"]

	if longtermkey == a.Config.LongTermKey {
		thirtyDays := 30 * 24 * 60 * 60
		req.Header.Add(TP_TOKEN_DURATION, string(thirtyDays))
	}

	//and now login
	a.Login(res, req)
}

func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	//we need server token
	a.requireServerToken(res, req)
	tokenString := vars["token"]

	svrToken := &models.SessionToken{Token: tokenString}
	if ok := svrToken.Verify(a.Config.ServerSecret); ok == true {
		sendModelAsRes(res, svrToken.TokenData)
	}
	res.WriteHeader(http.StatusNotFound)
	return
}

func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	//lets just try and remove the token
	if givenToken := models.GetSessionToken(req.Header.Get(TP_SESSION_TOKEN)); givenToken.Token != "" {
		if err := a.Store.RemoveToken(givenToken); err != nil {
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
	}
	res.WriteHeader(http.StatusBadRequest)
	return
}

func (a *Api) ManageIdHashPair(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	//we need server token
	a.requireServerToken(res, req)

	usr := &models.User{Id: vars["userid"]}
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
		}
		res.WriteHeader(http.StatusBadRequest)
	}
}
