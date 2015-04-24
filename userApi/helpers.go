package userapi

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/tidepool-org/go-common/clients/status"
)

const (
	TP_TOKEN_DURATION = "tokenduration"
)

//has a duration been set?
func tokenDuration(req *http.Request) (dur float64) {

	durString := req.Header.Get(TP_TOKEN_DURATION)

	if durString != "" {
		log.Printf("tokenDuration: given duration [%s]", durString)
		dur, _ = strconv.ParseFloat(durString, 64)
	}

	log.Printf("tokenDuration: set to [%f]", dur)

	return dur
}

//Docode the http.Request parsing out the user details
func getUserDetail(req *http.Request) (ud *UserDetail) {
	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&ud); err != nil {
			log.Println("error trying to decode user detail ", err)
			return ud
		}
	}
	log.Printf("User details [%v]", ud)
	return ud
}

//Docode the http.Request parsing out the user details
func getGivenDetail(req *http.Request) (d map[string]string) {
	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&d); err != nil {
			log.Println("error trying to decode user detail ", err)
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
			log.Print("Error unpacking authorization header [%s]", err.Error())
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
	return
}

func sendModelAsResWithStatus(res http.ResponseWriter, model interface{}, statusCode int) {
	res.Header().Set("content-type", "application/json")
	res.WriteHeader(statusCode)

	if jsonDetails, err := json.Marshal(model); err != nil {
		log.Println(err)
	} else {
		res.Write(jsonDetails)
	}
	return
}

func (a *Api) hasServerToken(tokenString string) bool {

	if td := a.getUnpackedToken(tokenString); td != nil {
		return td.IsServer
	}
	return false
}

//send metric
func (a *Api) logMetric(name, token string, params map[string]string) {
	if token == "" {
		log.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	log.Printf("log metric name[%s] params[%v]", name, params)
	//a.metrics.PostThisUser(name, token, params)
	return
}

//send metric
func (a *Api) logMetricAsServer(name, token string, params map[string]string) {
	if token == "" {
		log.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	log.Printf("log metric as server name[%s] params[%v]", name, params)
	//a.metrics.PostServer(name, token, params)
	return
}

//send metric
func (a *Api) logMetricForUser(id, name, token string, params map[string]string) {
	if token == "" {
		log.Println("Missing token so couldn't log metric")
		return
	}
	if params == nil {
		params = make(map[string]string)
	}
	log.Printf("log metric id[%s] name[%s] params[%v]", id, name, params)
	//a.metrics.PostWithUser(id, name, token, params)
	return
}

//get the token from the req header
func (a *Api) getUnpackedToken(tokenString string) *TokenData {
	if st := GetSessionToken(tokenString); st.Id != "" {
		if td := st.UnpackAndVerify(a.Config.Secret); td != nil && td.Valid == true {
			return td
		}
	}
	return nil
}

func (a *Api) addUserAndSendStatus(user *User, res http.ResponseWriter, req *http.Request) {
	if err := a.Store.UpsertUser(user); err != nil {
		log.Printf("addUserAndSendStatus %s err[%s]", STATUS_ERR_CREATING_USR, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_CREATING_USR), http.StatusInternalServerError)
		return
	}
	if sessionToken, err := a.createAndSaveToken(tokenDuration(req), user.Id, false); err != nil {
		log.Printf("addUserAndSendStatus %s err[%s]", STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else {
		a.logMetric("usercreated", sessionToken.Id, nil)
		res.Header().Set(TP_SESSION_TOKEN, sessionToken.Id)
		sendModelAsResWithStatus(res, user, http.StatusCreated)
		return
	}
}

func (a *Api) createAndSaveToken(dur float64, id string, isServer bool) (*SessionToken, error) {
	sessionToken, _ := NewSessionToken(
		&TokenData{
			UserId:       id,
			IsServer:     isServer,
			DurationSecs: dur,
		},
		a.Config.Secret,
	)

	if err := a.Store.AddToken(sessionToken); err == nil {
		return sessionToken, nil
	} else {
		return nil, err
	}
}
