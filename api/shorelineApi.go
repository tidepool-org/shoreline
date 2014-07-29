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
		config config
	}
	config struct {
		ServerSecret string
		LongTermKey  string
		Salt         string
	}
)

const (
	TP_SERVER_NAME    = "x-tidepool-server-name"
	TP_SERVER_SECRET  = "x-tidepool-server-secret"
	TP_SESSION_TOKEN  = "x-tidepool-session-token"
	TP_TOKEN_DURATION = "tokenduration"
)

func InitApi(store clients.StoreClient, cfg interface{}) *Api {
	return &Api{
		Store: store,
		config: config{
			ServerSecret: "shhh! don't tell",
			LongTermKey:  "the longetermkey",
			Salt:         "a mineral substance composed primarily of sodium chloride"},
	}
}

//Docode the http.Request parsing out the user model
func findUserDetail(res http.ResponseWriter, req *http.Request) (usr *models.User) {

	id := mux.Vars(req)["userid"]

	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&usr); err != nil {
			sendErrorAsRes(res, err)
		}
	}

	if usr != nil && id != "" {
		usr.Id = id
	} else if id != "" {
		usr = &models.User{Id: id}
	}

	return usr
}

//Log the error and return http.StatusInternalServerError code
func sendErrorAsRes(res http.ResponseWriter, err error) {
	if err != nil {
		log.Fatal(err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}
}

//Check token and return http.StatusUnauthorized if not found
func tokenCheck(res http.ResponseWriter, req *http.Request) {
	token := models.GetSessionToken(req.Header)
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
func unpackAuth(authLine string) (usr *models.User, err error) {

	if authLine == "" {
		//no auth header so return empty
		return &models.User{Name: "", Pw: ""}, nil
	} else {

		parts := strings.SplitN(authLine, " ", 2)
		payload := parts[1]
		decodedPayload, err := base64.URLEncoding.DecodeString(payload)
		if err != nil {
			return usr, err
		}

		details := strings.Split(string(decodedPayload), ":")

		return &models.User{Name: details[0], Pw: details[1]}, nil
	}
}

func sendModelsAsRes(res http.ResponseWriter, models ...interface{}) {

	res.WriteHeader(http.StatusOK)
	res.Header().Add("content-type", "application/json")

	res.Write([]byte("["))
	for i := range models {
		if jsonDetails, err := json.Marshal(models[i]); err != nil {
			log.Fatal(err)
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
		log.Fatal(err)
	} else {
		res.Write(jsonDetails)
	}
	return
}

func (a *Api) requireServerToken(res http.ResponseWriter, req *http.Request) {
	tokenCheck(res, req)

	svrToken := models.GetSessionToken(req.Header)

	if ok := svrToken.Verify(a.config.ServerSecret); ok == true {
		if svrToken.TokenData.IsServer {
			return
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
}

func getPathComonents(req *http.Request) []string {
	//The URL that the user queried.
	path := req.URL.Path
	path = strings.TrimSpace(path)

	//Cut off the leading and trailing forward slashes, if they exist.
	//This cuts off the leading forward slash.
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	//This cuts off the trailing forward slash.
	if strings.HasSuffix(path, "/") {
		cut_off_last_char_len := len(path) - 1
		path = path[:cut_off_last_char_len]
	}
	//We need to isolate the individual components of the path.
	components := strings.Split(path, "/")
	return components
}

//Pull the incoming user from the http.Request body and save return http.StatusCreated
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if usr := findUserDetail(res, req); usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		err := a.Store.UpsertUser(usr)

		sendErrorAsRes(res, err)

		res.WriteHeader(http.StatusCreated)
		return
	}
}

//Pull the incoming user updates from http.Request body and save return http.StatusOK
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request) {

	tokenCheck(res, req)

	if usr := findUserDetail(res, req); usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		err := a.Store.UpsertUser(usr)

		sendErrorAsRes(res, err)

		res.WriteHeader(http.StatusOK)
		return
	}
}

//Pull the incoming user feilds to search for from http.Request body and
//find any matches returning them with return http.StatusOK
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request) {

	tokenCheck(res, req)

	var usr *models.User

	//TODO: could be id or email infact
	id := mux.Vars(req)["userid"]
	if id != "" {
		usr = &models.User{Id: id}
	} else {
		//use the token to find the userid
		token := models.GetSessionToken(req.Header)
		token.Verify(a.config.ServerSecret)
		usr = &models.User{Id: token.TokenData.UserId}
	}

	if usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {
		if results, err := a.Store.FindUsers(usr); err != nil {
			sendErrorAsRes(res, err)
		} else {
			if len(results) == 1 && usr.Pw != "" {
				if results[0].HasPwMatch(usr, a.config.Salt) {
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

	if usr, err := unpackAuth(req.Header.Get("Authorization")); err != nil {
		sendErrorAsRes(res, err)
	} else if usr.Name == "" || usr.Pw == "" {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		if results, err := a.Store.FindUsers(usr); err != nil {
			sendErrorAsRes(res, err)
		} else if results != nil {

			for i := range results {
				//ensure a pw match
				if results[i].HasPwMatch(usr, a.config.Salt) {

					sessionToken, _ := models.NewSessionToken(
						&models.TokenData{
							UserId:   results[i].Id,
							IsServer: false,
							Duration: tokenDuration(req),
						},
						a.config.ServerSecret,
					)

					if err := a.Store.AddToken(sessionToken); err == nil {
						res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
						//postThisUser('userlogin', {}, sessiontoken);
						sendModelAsRes(res, results[0])
					} else {
						sendErrorAsRes(res, err)
					}
				}
			}
		}
	}

	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) ServerLogin(res http.ResponseWriter, req *http.Request) {

	server, pw := req.Header.Get(TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)

	if server == "" || pw == "" {
		res.WriteHeader(http.StatusBadRequest)
		return
	}
	if pw == a.config.ServerSecret {
		//generate new token

		sessionToken, _ := models.NewSessionToken(
			&models.TokenData{
				UserId:   server,
				IsServer: true,
				Duration: tokenDuration(req),
			},
			a.config.ServerSecret,
		)

		if err := a.Store.AddToken(sessionToken); err == nil {
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
			res.WriteHeader(http.StatusOK)
			//postServer('serverlogin', {}, sessiontoken);
			return
		} else {
			sendErrorAsRes(res, err)
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	const (
		TWO_HOURS_IN_SECS = 60 * 60 * 2
	)

	sessionToken := models.GetSessionToken(req.Header)

	if ok := sessionToken.Verify(a.config.ServerSecret); ok == true {

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
			a.config.ServerSecret,
		)

		if err := a.Store.AddToken(newToken); err == nil {
			res.Header().Set(TP_SESSION_TOKEN, newToken.Token)
			res.WriteHeader(http.StatusOK)
			//postServer('serverlogin', {}, sessiontoken);
			return
		} else {
			sendErrorAsRes(res, err)
		}

	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) LongtermLogin(res http.ResponseWriter, req *http.Request) {

	longtermkey := mux.Vars(req)["longtermkey"]

	if longtermkey == a.config.LongTermKey {
		thirtyDays := 30 * 24 * 60 * 60
		req.Header.Add(TP_TOKEN_DURATION, string(thirtyDays))
	}

	//and now login
	a.Login(res, req)
}

func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request) {

	//we need server token
	a.requireServerToken(res, req)
	tokenString := mux.Vars(req)["token"]
	if tokenString == "" {
		parts := getPathComonents(req)
		tokenString = parts[0]
	}

	svrToken := &models.SessionToken{Token: tokenString}
	if ok := svrToken.Verify(a.config.ServerSecret); ok == true {
		sendModelAsRes(res, svrToken.TokenData)
	}
	res.WriteHeader(http.StatusNotFound)
	return
}

func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	//lets just try and remove the token
	if givenToken := models.GetSessionToken(req.Header); givenToken.Token != "" {
		if err := a.Store.RemoveToken(givenToken); err != nil {
			log.Fatal("Unable to delete token.", err)
		}
	}
	//otherwise all good
	res.WriteHeader(http.StatusOK)
	return
}

func (a *Api) AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	if len(req.URL.Query()) > 0 {
		idHashPair := models.NewAnonIdHashPair([]string{a.config.Salt}, req.URL.Query())
		sendModelAsRes(res, idHashPair)
	}
	res.WriteHeader(http.StatusBadRequest)
	return
}

func (a *Api) ManageIdHashPair(res http.ResponseWriter, req *http.Request) {

	//we need server token
	a.requireServerToken(res, req)

	params := mux.Vars(req)

	usr := &models.User{Id: params["userid"]}
	theKey := params["key"]

	baseStrings := []string{a.config.Salt, usr.Id, theKey}

	if foundUsr, err := a.Store.FindUser(usr); err != nil {
		sendErrorAsRes(res, err)
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
					sendErrorAsRes(res, err)
				} else {
					sendModelAsRes(res, foundUsr.Private[theKey])
				}
			}
		case "POST", "PUT":
			if foundUsr.Private == nil {
				foundUsr.Private = make(map[string]*models.IdHashPair)
			}
			foundUsr.Private[theKey] = models.NewIdHashPair(baseStrings, req.URL.Query())

			if err := a.Store.UpsertUser(foundUsr); err != nil {
				sendErrorAsRes(res, err)
			} else {
				sendModelAsResWithStatus(res, foundUsr.Private[theKey], http.StatusCreated)
			}
		case "DELETE":
			res.WriteHeader(http.StatusNotImplemented)
		}
		res.WriteHeader(http.StatusBadRequest)
	}
}
