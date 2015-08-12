package user

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/tidepool-org/go-common/clients/status"
)

//Docode the http.Request parsing out the user details
func getGivenDetail(req *http.Request) (d map[string]string) {
	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&d); err != nil {
			log.Print(USER_API_PREFIX, "error trying to decode user detail ", err)
			return nil
		}
	}
	return d
}

// Extract the username and password from the authorization
// line of an HTTP header. This function will handle the
// parsing and decoding of the line.
func unpackAuth(authLine string) (usr *User, pw string) {
	if authLine != "" {
		parts := strings.SplitN(authLine, " ", 2)
		payload := parts[1]
		if decodedPayload, err := base64.URLEncoding.DecodeString(payload); err != nil {
			log.Print(USER_API_PREFIX, "Error unpacking authorization header [%s]", err.Error())
		} else {
			details := strings.Split(string(decodedPayload), ":")
			if details[0] != "" || details[1] != "" {
				//Note the incoming `name` could infact be id, email or the username
				return UserFromDetails(&UserDetail{Id: details[0], Name: details[0], Emails: []string{details[0]}}), details[1]
			}
		}
	}
	return nil, ""
}

func sendModelsAsRes(res http.ResponseWriter, models ...interface{}) {

	res.Header().Set("content-type", "application/json")
	res.WriteHeader(http.StatusOK)

	res.Write([]byte("["))
	for i := range models {
		if jsonDetails, err := json.Marshal(models[i]); err != nil {
			log.Println(USER_API_PREFIX, err.Error())
		} else {
			res.Write(jsonDetails)
		}
	}
	res.Write([]byte("]"))
	return
}

func sendModelAsRes(res http.ResponseWriter, model interface{}) {
	sendModelAsResWithStatus(res, model, http.StatusOK)
	return
}

func sendModelAsResWithStatus(res http.ResponseWriter, model interface{}, statusCode int) {
	res.Header().Set("content-type", "application/json")
	res.WriteHeader(statusCode)

	if jsonDetails, err := json.Marshal(model); err != nil {
		log.Println(USER_API_PREFIX, err.Error())
	} else {
		res.Write(jsonDetails)
	}
	return
}

//send metric
func (a *Api) logMetric(name, token string, params map[string]string) {
	if token == "" {
		a.logger.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	a.metrics.PostThisUser(name, token, params)
	return
}

//send metric
func (a *Api) logMetricAsServer(name, token string, params map[string]string) {
	if token == "" {
		a.logger.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	a.metrics.PostServer(name, token, params)
	return
}

//send metric
func (a *Api) logMetricForUser(id, name, token string, params map[string]string) {
	if token == "" {
		a.logger.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	a.metrics.PostWithUser(id, name, token, params)
	return
}

func (a *Api) addUserAndSendStatus(user *User, res http.ResponseWriter, req *http.Request) {
	if err := a.Store.UpsertUser(user); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_CREATING_USR), http.StatusInternalServerError)
		return
	}
	if sessionToken, err := CreateSessionTokenAndSave(
		&TokenData{DurationSecs: extractTokenDuration(req), UserId: user.Id, IsServer: false},
		TokenConfig{DurationHours: a.ApiConfig.TokenHoursDuration, Secret: a.ApiConfig.Secret},
		a.Store); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else {
		a.logMetric("usercreated", sessionToken.Id, nil)
		res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
		sendModelAsResWithStatus(res, user, http.StatusCreated)
		return
	}
}
