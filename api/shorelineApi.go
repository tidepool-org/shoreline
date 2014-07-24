package api

import (
	"encoding/base64"
	"encoding/json"
	"github.com/tidepool-org/shoreline/clients"
	"github.com/tidepool-org/shoreline/models"
	"log"
	"net/http"
	"strings"
)

type (
	Api struct {
		Store  clients.StoreClient
		config config
	}
	config struct {
		ServerSecret string
		Salt         string
	}
)

const (
	TP_SERVER_NAME   = "x-tidepool-server-name"
	TP_SERVER_SECRET = "x-tidepool-server-secret"
	TP_SESSION_TOKEN = "x-tidepool-session-token"
)

func InitApi(store clients.StoreClient) *Api {
	return &Api{Store: store, config: config{ServerSecret: "shhh! don't tell", Salt: "a mineral substance composed primarily of sodium chloride"}}
}

//Docode the http.Request parsing out the user model
func findUserDetail(res http.ResponseWriter, req *http.Request) (usr *models.User) {

	id := req.URL.Query().Get("userid")

	//do we also have details in the body?
	if req.Body != nil {
		if err := json.NewDecoder(req.Body).Decode(&usr); err != nil {
			errorRes(res, err)
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
func errorRes(res http.ResponseWriter, err error) {
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

func sendModelsJsonRes(res http.ResponseWriter, models []interface{}) {

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

func sendModelJsonRes(res http.ResponseWriter, model interface{}) {

	res.WriteHeader(http.StatusOK)
	res.Header().Add("content-type", "application/json")

	if jsonDetails, err := json.Marshal(model); err != nil {
		log.Fatal(err)
	} else {
		res.Write(jsonDetails)
	}
	return
}

//Pull the incoming user from the http.Request body and save return http.StatusCreated
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if usr := findUserDetail(res, req); usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		err := a.Store.UpsertUser(usr)

		errorRes(res, err)

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

		errorRes(res, err)

		res.WriteHeader(http.StatusOK)
		return
	}
}

//Pull the incoming user feilds to search for from http.Request body and
//find any matches returning them with return http.StatusOK
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request) {

	tokenCheck(res, req)

	if usr := findUserDetail(res, req); usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		if results, err := a.Store.FindUser(usr); err != nil {
			errorRes(res, err)
		} else {
			sendModelJsonRes(res, results)
		}

		return
	}
}

//TODO:
func (a *Api) DeleteUser(res http.ResponseWriter, req *http.Request) {

	tokenCheck(res, req)

	res.WriteHeader(501)
}

func (a *Api) Login(res http.ResponseWriter, req *http.Request) {

	if usr, err := unpackAuth(req.Header.Get("Authorization")); err != nil {
		errorRes(res, err)
	} else if usr.Name == "" || usr.Pw == "" {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		if results, err := a.Store.FindUser(usr); err != nil {
			errorRes(res, err)
		} else if results != nil && results.Id != "" {
			sessionToken, _ := models.NewSessionToken(&models.TokenData{UserId: results.Id, IsServer: false, Duration: 3600}, a.config.ServerSecret)

			if err := a.Store.AddToken(sessionToken); err == nil {
				res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
				//postThisUser('userlogin', {}, sessiontoken);
				sendModelJsonRes(res, results)
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
		sessionToken, _ := models.NewSessionToken(&models.TokenData{UserId: server, IsServer: true, Duration: 3600}, a.config.ServerSecret)

		if err := a.Store.AddToken(sessionToken); err == nil {
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
			res.WriteHeader(http.StatusOK)
			//postServer('serverlogin', {}, sessiontoken);
			return
		} else {
			errorRes(res, err)
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	sessionToken := models.GetSessionToken(req.Header)

	if ok := sessionToken.Verify(a.config.ServerSecret); ok == true {

		if sessionToken.TokenData.IsServer == false && sessionToken.TokenData.Duration > 60*60*2 {
			//long-duration, it's not renewable, so just return it
			sendModelJsonRes(res, sessionToken.TokenData.UserId)
		}
		//sessionToken, _ := models.NewSessionToken(server, a.config.ServerSecret, 1000, true)

		newToken, _ := models.NewSessionToken(
			&models.TokenData{
				UserId:   sessionToken.TokenData.UserId,
				Duration: 10000,
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
			errorRes(res, err)
		}

	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

//set the tokenduration
func (a *Api) ValidateLongterm(res http.ResponseWriter, req *http.Request) {

	/*if (req.params.longtermkey != null && req.params.longtermkey === envConfig.longtermkey) {
	    req.tokenduration = 30 * 24 * 60 * 60; // 30 days
	  }
	  return next();
	*/

	res.WriteHeader(501)
}

func (a *Api) RequireServerToken(res http.ResponseWriter, req *http.Request) {
	tokenCheck(res, req)

	svrToken := models.GetSessionToken(req.Header)

	if ok := svrToken.Verify(a.config.ServerSecret); ok == true {
		if svrToken.TokenData.IsServer {
			return
		}
	}
	res.WriteHeader(http.StatusUnauthorized)
	return
}

func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request) {

	givenToken := models.GetSessionToken(req.Header)
	if ok := givenToken.Verify(a.config.ServerSecret); ok == true {

		sendModelJsonRes(res, givenToken.TokenData)
	}
	res.WriteHeader(http.StatusNotFound)
	return
}

func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	//lets just try and remove the token
	if givenToken := models.GetSessionToken(req.Header); givenToken.Token != "" {
		if err := a.Store.RemoveToken(givenToken.Token); err != nil {
			log.Fatal("Unable to delete token.", err)
		}
	}
	//otherwise all good
	res.WriteHeader(http.StatusOK)
	return
}

func (a *Api) AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	theStrings := []string{a.config.Salt}
	queryValues := req.URL.Query()

	if len(queryValues) > 0 {

		for k, v := range queryValues {
			theStrings = append(theStrings, k)
			theStrings = append(theStrings, v[0])
		}

		idHashPair := models.NewIdHashPair("", theStrings)

		sendModelJsonRes(res, idHashPair)
	}
	res.WriteHeader(http.StatusBadRequest)
	return
}

func (a *Api) ManageIdHashPair(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}
