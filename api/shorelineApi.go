package api

import (
	"encoding/json"
	clients "github.com/tidepool-org/shoreline/clients"
	models "github.com/tidepool-org/shoreline/models"
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

func decodeBody(res http.ResponseWriter, req *http.Request) (usr *models.User) {
	if req.Body == nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(req.Body).Decode(&usr)

	onError(res, err)

	return usr
}

func onError(res http.ResponseWriter, err error) {
	if err != nil {
		res.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func tokenCheck(res http.ResponseWriter, req *http.Request) {
	token := models.GetSessionToken(req.Header)
	if token.Token == "" {
		res.WriteHeader(401)
		return
	}
}

func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	usr := decodeBody(res, req)

	err := a.Store.UpsertUser(usr)

	onError(res, err)

	res.WriteHeader(http.StatusCreated)
	return
}

func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request) {

	tokenCheck(res, req)
	usr := decodeBody(res, req)

	err := a.Store.UpsertUser(usr)

	onError(res, err)

	res.WriteHeader(http.StatusOK)
	return
}

func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request) {

	tokenCheck(res, req)

	res.WriteHeader(501)
}

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
