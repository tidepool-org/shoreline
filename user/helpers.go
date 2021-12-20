package user

import (
	"container/list"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mdblp/shoreline/token"
)

// Input Sanitizer
func sanitize(el string) string {
	return bmPolicy.Sanitize(el)
}

func sanitizeRequestParam(req *http.Request, paramName string) string {
	return sanitize(req.URL.Query().Get(paramName))
}

func sanitizeRequestHeader(req *http.Request, headerName string) string {
	return sanitize(req.Header.Get(headerName))
}

func sanitizeSessionToken(req *http.Request) string {
	return sanitizeRequestHeader(req, TP_SESSION_TOKEN)
}

func sanitizeSessionTrace(req *http.Request) string {
	return sanitizeRequestHeader(req, TP_TRACE_SESSION)
}

// getIntFromEnvVar return an int from the os env var
//
// if you are not interested in minValue/maxValue, use: math.MinInt32 / math.MaxInt32
func getIntFromEnvVar(name string, minValue int, maxValue int) (int, bool, error) {
	var intValue int
	var err error
	strValue, found := os.LookupEnv(name)
	if found && len(strValue) > 0 {
		if intValue, err = strconv.Atoi(strValue); err != nil {
			return 0, true, fmt.Errorf("invalid value for %s: '%s'", name, strValue)
		}
		if intValue < minValue {
			return 0, true, fmt.Errorf("value too low for %s: '%s'", name, strValue)
		}
		if intValue > maxValue {
			return 0, true, fmt.Errorf("value too high for %s: '%s'", name, strValue)
		}
		return intValue, true, nil
	}
	return 0, false, nil
}

func firstStringNotEmpty(strs ...string) string {
	for _, str := range strs {
		if len(str) > 0 {
			return str
		}
	}
	return ""
}

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

// fromISO8859 is a workaround to accept strings not encoded in UT8 and containing non ascii characters
//
// Javascript & Java by default try to encode their base64 string using
// UTF-16 or ISO-8859-1 if the Unicode code point value is less than 0xFF
// ISO-8859-1 has the same codepoints than Unicode for 0x00 - 0xFF range
//
// Try to decode the bytes as if each byte is an Unicode code point.
func fromISO8859(b []byte) string {
	var u16s []rune = make([]rune, len(b))
	for i, j := 0, len(b); i < j; i++ {
		u16s[i] = rune(b[i])
	}
	return string(u16s)
}

// Extract the username and password from the authorization
// line of an HTTP header. This function will handle the
// parsing and decoding of the line.
//
// Return the user to pass to the mongo find function, the password
// and an error or nil if there is no error
func unpackAuth(authLine string) (user *User, passwd string, err error) {
	var decodedPayload []byte
	var strPayload string
	if authLine != "" {
		parts := strings.SplitN(authLine, " ", 2)
		payload := parts[1]
		if decodedPayload, err = base64.StdEncoding.DecodeString(payload); err != nil {
			return nil, "", err
		}
		if utf8.Valid(decodedPayload) {
			strPayload = string(decodedPayload)
		} else {
			log.Printf("%s authorization: Invalid UTF-8 decoded string, trying with ISO-8859-1", USER_API_PREFIX)
			strPayload = fromISO8859(decodedPayload)
		}

		details := strings.SplitN(strPayload, ":", 2)
		if details[0] != "" || details[1] != "" {
			//Note the incoming `name` could infact be id, email or the username
			return &User{Id: details[0], Username: details[0], Emails: []string{details[0]}}, details[1], nil
		}
	}
	return nil, "", errors.New("empty authorization line")
}

func sendModelAsRes(res http.ResponseWriter, model interface{}) {
	sendModelAsResWithStatus(res, model, http.StatusOK)
}

func sendModelAsResWithStatus(res http.ResponseWriter, model interface{}, statusCode int) {
	res.Header().Set("content-type", "application/json")
	res.WriteHeader(statusCode)

	if jsonDetails, err := json.Marshal(model); err != nil {
		log.Println(USER_API_PREFIX, err.Error())
	} else {
		res.Write(jsonDetails)
	}
}

// logAudit Variatic log for audit trails
func (a *Api) logAudit(req *http.Request, tokenData *token.TokenData, format string, args ...interface{}) {
	var prefix string

	if req.RemoteAddr != "" {
		prefix = fmt.Sprintf("remoteAddr{%s}, ", req.RemoteAddr)
	}

	traceSession := sanitizeSessionTrace(req)
	if traceSession != "" {
		prefix += fmt.Sprintf("trace{%s}, ", traceSession)
	}

	if tokenData != nil {
		prefix += fmt.Sprintf("isServer{%t}, ", tokenData.IsServer)
	}

	s := fmt.Sprintf(format, args...)
	a.auditLogger.Printf("%s%s", prefix, s)
}

func (a *Api) sendUser(res http.ResponseWriter, user *User, isServerRequest bool) {
	a.sendUserWithStatus(res, user, http.StatusOK, isServerRequest)
}

func (a *Api) sendUserWithStatus(res http.ResponseWriter, user *User, statusCode int, isServerRequest bool) {
	sendModelAsResWithStatus(res, a.asSerializableUser(user, isServerRequest), statusCode)
}

func (a *Api) sendUsers(res http.ResponseWriter, users []*User, isServerRequest bool) {
	serializables := make([]interface{}, len(users))
	for index, user := range users {
		serializables[index] = a.asSerializableUser(user, isServerRequest)
	}
	sendModelAsRes(res, serializables)
}

func (a *Api) asSerializableUser(user *User, isServerRequest bool) interface{} {
	serializable := make(map[string]interface{})
	if len(user.Id) > 0 {
		serializable["userid"] = user.Id
	}
	if len(user.Username) > 0 {
		serializable["username"] = user.Username
	}
	if len(user.Emails) > 0 {
		serializable["emails"] = user.Emails
	}
	if len(user.Roles) > 0 {
		serializable["roles"] = user.Roles
	}
	if len(user.TermsAccepted) > 0 {
		serializable["termsAccepted"] = user.TermsAccepted
	}
	if len(user.Username) > 0 || len(user.Emails) > 0 {
		serializable["emailVerified"] = user.EmailVerified
	}
	if isServerRequest {
		serializable["passwordExists"] = (user.PwHash != "")
	}
	return serializable
}

func (a *Api) appendUserLoginInProgress(user *User) (code int, elem *list.Element) {
	a.loginLimiter.mutex.Lock()
	defer a.loginLimiter.mutex.Unlock()

	// Simple rate limiter
	a.loginLimiter.totalInProgress++
	inFligthLogin.Add(1)

	if a.loginLimiter.totalInProgress > a.ApiConfig.MaxConcurrentLogin {
		return http.StatusTooManyRequests, nil
	}
	var loggedUser *list.Element
	if a.ApiConfig.BlockParallelLogin {
		for e := a.loginLimiter.usersInProgress.Front(); e != nil; e = e.Next() {
			if e.Value.(*User).Username == user.Username {
				return http.StatusTooManyRequests, nil
			}
		}
		loggedUser = a.loginLimiter.usersInProgress.PushBack(user)
	}
	return http.StatusOK, loggedUser
}

func (a *Api) removeUserLoginInProgress(elem *list.Element) {
	a.loginLimiter.mutex.Lock()

	a.loginLimiter.totalInProgress--
	inFligthLogin.Add(-1)

	if elem != nil {
		a.loginLimiter.usersInProgress.Remove(elem)
	}
	a.loginLimiter.mutex.Unlock()
}

func CreateSessionTokenAndSave(ctx context.Context, data *token.TokenData, config token.TokenConfig, store Storage) (*token.SessionToken, error) {
	sessionToken, err := token.CreateSessionToken(data, config)
	if err != nil {
		return nil, err
	}

	err = store.AddToken(ctx, sessionToken)
	if err != nil {
		return nil, err
	}

	return sessionToken, nil
}

func extractTokenDuration(r *http.Request) int64 {
	durString := r.Header.Get(token.TOKEN_DURATION_KEY)

	if durString != "" {
		//if there is an error we just return a duration of zero
		dur, err := strconv.ParseInt(durString, 10, 64)
		if err == nil {
			return dur
		}
	}
	return 0
}

func hasServerToken(tokenString, secret string) bool {
	td, err := token.UnpackSessionTokenAndVerify(tokenString, secret)
	if err != nil {
		return false
	}
	return td.IsServer
}
