package api

import (
	"encoding/json"
	clients "github.com/tidepool-org/shoreline/clients"
	models "github.com/tidepool-org/shoreline/models"
	"log"
	"net/http"
)

type (
	Api struct {
		Store clients.StoreClient
	}
)

func InitApi(store clients.StoreClient) *Api {
	return &Api{Store: store}
}

//Docode the http.Request parsing out the user model
func findUserDetail(res http.ResponseWriter, req *http.Request) (usr *models.User) {

	id := req.URL.Query().Get("userid")

	//do we also have details in the body?
	if req.Body != nil {
		if err := json.NewDecoder(req.Body).Decode(&usr); err != nil {
			onError(res, err)
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
func onError(res http.ResponseWriter, err error) {
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

//Pull the incoming user from the http.Request body and save return http.StatusCreated
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if usr := findUserDetail(res, req); usr == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	} else {

		err := a.Store.UpsertUser(usr)

		onError(res, err)

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

		onError(res, err)

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

		results, err := a.Store.FindUser(usr)

		onError(res, err)

		res.WriteHeader(http.StatusOK)
		res.Header().Add("content-type", "application/json")
		res.Write([]byte("["))
		bytes, err := json.Marshal(results)
		if err != nil {
			log.Fatal(err)
		}
		res.Write(bytes)
		res.Write([]byte("]"))

		return
	}
}

//TODO:
func (a *Api) DeleteUser(res http.ResponseWriter, req *http.Request) {

	tokenCheck(res, req)

	res.WriteHeader(501)
}

func (a *Api) Login(res http.ResponseWriter, req *http.Request) {

	if req.Header.Get("Authorization") == "" {
		res.WriteHeader(400)
		return
	}

	res.WriteHeader(501)
}

func (a *Api) ServerLogin(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
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
