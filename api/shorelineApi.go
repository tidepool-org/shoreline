package api

import (
	clients "github.com/tidepool-org/shoreline/clients"
	models "github.com/tidepool-org/shoreline/models"
	"net/http"
	"net/url"
)

type Api struct {
	Store clients.StoreClient
}

func InitApi(store clients.StoreClient) *Api {
	return &Api{Store: store}
}

func hasParams(query url.Values, params []string) bool {
	var ok bool

	for i := range params {

		_, ok = query[params[i]]

		if ok == false {
			return ok
		}
	}
	return ok
}

func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {

	if hasParams(req.URL.Query(), []string{"username", "emails", "password"}) == false {
		res.WriteHeader(400)
		return
	}
	res.WriteHeader(501)

}

func UpdateUser(res http.ResponseWriter, req *http.Request) {

	token := models.GetSessionToken(req.Header)
	if token.Token == "" {
		res.WriteHeader(401)
		return
	}

	res.WriteHeader(501)
}

func GetUserInfo(res http.ResponseWriter, req *http.Request) {

	token := models.GetSessionToken(req.Header)
	if token.Token == "" {
		res.WriteHeader(401)
		return
	}

	res.WriteHeader(501)
}

func DeleteUser(res http.ResponseWriter, req *http.Request) {

	token := models.GetSessionToken(req.Header)
	if token.Token == "" {
		res.WriteHeader(401)
		return
	}

	res.WriteHeader(501)
}

func Login(res http.ResponseWriter, req *http.Request) {

	if req.Header.Get("Authorization") == "" {
		res.WriteHeader(400)
		return
	}
	res.WriteHeader(501)
}

func ServerLogin(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func RefreshSession(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func ValidateLongterm(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func RequireServerToken(res http.ResponseWriter, req *http.Request) {
	token := models.GetSessionToken(req.Header)
	if token.Token == "" {
		res.WriteHeader(401)
		return
	}

	res.WriteHeader(501)
}

func ServerCheckToken(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func Logout(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func ManageIdHashPair(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}
