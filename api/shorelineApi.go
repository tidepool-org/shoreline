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
	return &Api{Store: store, config: config{ServerSecret: "shhh! don't tell"}}
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

func usersRes(res http.ResponseWriter, users []*models.User) {

	res.WriteHeader(http.StatusOK)
	res.Header().Add("content-type", "application/json")

	if len(users) > 1 {
		res.Write([]byte("["))
		for i := range users {
			bytes, err := json.Marshal(users[i])
			if err != nil {
				log.Fatal(err)
			}
			res.Write(bytes)
		}
		res.Write([]byte("]"))
		return
	} else if len(users) == 1 {
		bytes, err := json.Marshal(users[0])
		if err != nil {
			log.Fatal(err)
		}
		res.Write(bytes)
		return
	}
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
			usersRes(res, []*models.User{results})
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
			//TODO: the secret!!!
			sessionToken, _ := models.NewSessionToken(results.Id, "make it secret", 1000, false)

			if err := a.Store.AddToken(sessionToken); err == nil {
				res.Header().Set(TP_SESSION_TOKEN, sessionToken.Token)
				//userid username emails
				usersRes(res, []*models.User{results})
				//postThisUser('userlogin', {}, sessiontoken);
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
		res.WriteHeader(http.StatusOK)
		return
	}
	res.WriteHeader(http.StatusUnauthorized)
	return

	/*
			var server = req.headers['x-tidepool-server-name'];
		    var pw = req.headers['x-tidepool-server-secret'];

		    if (!(server && pw)) {
		      log.warn('Machine login attempted with missing information');
		      res.send(400, 'Missing login information');
		      return next();
		    }

		    if (pw === envConfig.serverSecret) {
		      // we're good, create a token
		      var sessiontoken = getSessionToken(server, req.tokenduration, true);
		      upsertToken(sessiontoken, function (err, stored) {
		        res.header('x-tidepool-session-token', sessiontoken);
		        res.send(200, 'machine login');
		        postServer('serverlogin', {}, sessiontoken);
		        return next();
		      });
		    } else {
		      log.warn('Machine login attempted with bad login info. server[%s], host[%s]', server, req.connection.remoteAddress);
		      res.send(401, 'Server identity not validated!');
		      return next();
		    }
	*/

}

func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func (a *Api) ValidateLongterm(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func (a *Api) RequireServerToken(res http.ResponseWriter, req *http.Request) {
	tokenCheck(res, req)

	res.WriteHeader(501)
}

func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func (a *Api) AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func (a *Api) ManageIdHashPair(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}
