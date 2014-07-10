package api

import (
	"net/http"
)

func CreateUser(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func UpdateUser(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func GetUserInfo(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(501)
}

func DeleteUser(res http.ResponseWriter, req *http.Request) {

	sessiontoken := req.Header.Get("x-tidepool-session-token")
	if sessiontoken == "" {
		res.WriteHeader(401)
		return
	}

	res.WriteHeader(501)
}

func Login(res http.ResponseWriter, req *http.Request) {
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
