package user

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/highwater"
	"github.com/tidepool-org/go-common/clients/status"
	"github.com/tidepool-org/shoreline/common"
	"github.com/tidepool-org/shoreline/oauth2"
	"github.com/tidepool-org/shoreline/user/mailchimp"
)

type (
	Api struct {
		Store            Storage
		ApiConfig        ApiConfig
		metrics          highwater.Client
		perms            clients.Gatekeeper
		oauth            oauth2.Client
		logger           *log.Logger
		mailchimpManager mailchimp.Manager
	}
	Secret struct {
		Secret string `json:"secret"`
		Pass   string `json:"pass"`
	}
	ApiConfig struct {
		//used for services
		Secrets              []Secret `json:"secrets"`
		ServerSecrets        map[string]string
		LongTermKey          string `json:"longTermKey"`
		LongTermDaysDuration int    `json:"longTermDaysDuration"`
		//so we can change the default lifetime of the token
		//we use seconds, this also helps for testing as you can time it out easily
		TokenDurationSecs int64 `json:"tokenDurationSecs"`
		//used for pw
		Salt string `json:"salt"`
		//used for token
		Secret string `json:"apiSecret"`
		//allows for the skipping of verification for testing
		VerificationSecret string           `json:"verificationSecret"`
		ClinicDemoUserID   string           `json:"clinicDemoUserId"`
		Mailchimp          mailchimp.Config `json:"mailchimp"`
	}
	varsHandler func(http.ResponseWriter, *http.Request, map[string]string)
)

const (
	//api logging prefix
	USER_API_PREFIX = "api/user "

	TP_SERVER_NAME   = "x-tidepool-server-name"
	TP_SERVER_SECRET = "x-tidepool-server-secret"
	TP_SESSION_TOKEN = "x-tidepool-session-token"

	STATUS_NO_USR_DETAILS        = "No user details were given"
	STATUS_INVALID_USER_DETAILS  = "Invalid user details were given"
	STATUS_USER_NOT_FOUND        = "User not found"
	STATUS_ERR_FINDING_USR       = "Error finding user"
	STATUS_ERR_CREATING_USR      = "Error creating the user"
	STATUS_ERR_UPDATING_USR      = "Error updating user"
	STATUS_USR_ALREADY_EXISTS    = "User already exists"
	STATUS_ERR_GENERATING_TOKEN  = "Error generating the token"
	STATUS_ERR_UPDATING_TOKEN    = "Error updating token"
	STATUS_MISSING_USR_DETAILS   = "Not all required details were given"
	STATUS_ERROR_UPDATING_PW     = "Error updating password"
	STATUS_MISSING_ID_PW         = "Missing id and/or password"
	STATUS_NO_MATCH              = "No user matched the given details"
	STATUS_NOT_VERIFIED          = "The user hasn't verified this account yet"
	STATUS_NO_TOKEN_MATCH        = "No token matched the given details"
	STATUS_PW_WRONG              = "Wrong password"
	STATUS_ERR_SENDING_EMAIL     = "Error sending email"
	STATUS_NO_TOKEN              = "No x-tidepool-session-token was found"
	STATUS_SERVER_TOKEN_REQUIRED = "A server token is required"
	STATUS_AUTH_HEADER_REQUIRED  = "Authorization header is required"
	STATUS_AUTH_HEADER_INVLAID   = "Authorization header is invalid"
	STATUS_GETSTATUS_ERR         = "Error checking service status"
	STATUS_UNAUTHORIZED          = "Not authorized for requested operation"
	STATUS_NO_QUERY              = "A query must be specified"
	STATUS_INVALID_ROLE          = "The role specified is invalid"
	STATUS_OK                    = "OK"
	STATUS_NO_EXPECTED_PWD       = "No expected password is found"
)

func InitApi(cfg ApiConfig, store Storage, metrics highwater.Client) *Api {
	logger := log.New(os.Stdout, USER_API_PREFIX, log.LstdFlags|log.Lshortfile)

	mailchimpManager, err := mailchimp.NewManager(logger, &http.Client{Timeout: 15 * time.Second}, &cfg.Mailchimp)
	if err != nil {
		logger.Println("WARNING: Mailchimp Manager not configured;", err)
	}

	// Server secrets retrieved from configuration are transformed into a hashtable for ease of access
	// They are stored in a public property called ServerSecrets
	cfg.ServerSecrets = make(map[string]string)
	for _, sec := range cfg.Secrets {
		cfg.ServerSecrets[sec.Secret] = sec.Pass
	}

	return &Api{
		Store:            store,
		ApiConfig:        cfg,
		metrics:          metrics,
		logger:           logger,
		mailchimpManager: mailchimpManager,
	}
}

func (a *Api) AttachPerms(perms clients.Gatekeeper) {
	a.perms = perms
}

func (a *Api) AttachOauth(client oauth2.Client) {
	a.oauth = client
}

func (a *Api) SetHandlers(prefix string, rtr *mux.Router) {
	rtr.HandleFunc("/status", a.GetStatus).Methods("GET")

	rtr.HandleFunc("/users", a.GetUsers).Methods("GET")

	rtr.Handle("/user", varsHandler(a.GetUserInfo)).Methods("GET")
	rtr.Handle("/user/{userid}", varsHandler(a.GetUserInfo)).Methods("GET")

	rtr.HandleFunc("/user", a.CreateUser).Methods("POST")
	rtr.Handle("/user", varsHandler(a.UpdateUser)).Methods("PUT")
	rtr.Handle("/user/{userid}", varsHandler(a.UpdateUser)).Methods("PUT")
	rtr.Handle("/user/{userid}", varsHandler(a.DeleteUser)).Methods("DELETE")

	rtr.Handle("/user/{userid}/user", varsHandler(a.CreateCustodialUser)).Methods("POST")

	rtr.HandleFunc("/login", a.Login).Methods("POST")
	rtr.HandleFunc("/login", a.RefreshSession).Methods("GET")
	rtr.Handle("/login/{longtermkey}", varsHandler(a.LongtermLogin)).Methods("POST")

	rtr.HandleFunc("/oauthlogin", a.oauth2Login).Methods("POST")

	rtr.HandleFunc("/serverlogin", a.ServerLogin).Methods("POST")

	rtr.Handle("/token/{token}", varsHandler(a.ServerCheckToken)).Methods("GET")

	rtr.HandleFunc("/logout", a.Logout).Methods("POST")

	rtr.HandleFunc("/private", a.AnonymousIdHashPair).Methods("GET")
}

func (h varsHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	h(res, req, vars)
}

func (a *Api) GetStatus(res http.ResponseWriter, req *http.Request) {
	if err := a.Store.Ping(); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_GETSTATUS_ERR, err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(err.Error()))
		return
	}
	res.WriteHeader(http.StatusOK)
	res.Write([]byte(STATUS_OK))
	return
}

//
// status: 200
// status: 400 STATUS_NO_ROLE
// status: 401 STATUS_SERVER_TOKEN_REQUIRED
// status: 500 STATUS_ERR_FINDING_USR
func (a *Api) GetUsers(res http.ResponseWriter, req *http.Request) {
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)

	} else if !tokenData.IsServer {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED)

	} else if role := req.URL.Query().Get("role"); role != "" && !IsValidRole(role) {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_ROLE)

	} else if role == "" {
		a.sendError(res, http.StatusBadRequest, STATUS_NO_QUERY)

	} else if users, err := a.Store.FindUsersByRole(role); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())

	} else {
		a.logMetric("getusers", sessionToken, map[string]string{"server": strconv.FormatBool(tokenData.IsServer)})
		a.sendUsers(res, users, tokenData.IsServer)
	}
}

// status: 201 User
// status: 400 STATUS_MISSING_USR_DETAILS
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {
	if newUserDetails, err := ParseNewUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if err := newUserDetails.Validate(); err != nil { // TODO: Fix this duplicate work!
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if newUser, err := NewUser(newUserDetails, a.ApiConfig.Salt); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else if existingUser, err := a.Store.FindUsers(newUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else if len(existingUser) != 0 {
		a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)

	} else if err := a.Store.UpsertUser(newUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else {
		if newUser.IsClinic() {
			if a.ApiConfig.ClinicDemoUserID != "" {
				if _, err := a.perms.SetPermissions(newUser.Id, a.ApiConfig.ClinicDemoUserID, clients.Permissions{"view": clients.Allowed}); err != nil {
					a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
					return
				}
			}
		}

		tokenData := TokenData{DurationSecs: extractTokenDuration(req), UserId: newUser.Id, IsServer: false}
		tokenConfig := TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret}
		if sessionToken, err := CreateSessionTokenAndSave(&tokenData, tokenConfig, a.Store); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err)
		} else {
			a.logMetricForUser(newUser.Id, "usercreated", sessionToken.ID, map[string]string{"server": "false"})
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			a.sendUserWithStatus(res, newUser, http.StatusCreated, false)
		}
	}
}

// status: 201 User
// status: 400 STATUS_MISSING_USR_DETAILS
// status: 401 STATUS_UNAUTHORIZED
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) CreateCustodialUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)

	} else if custodianUserId := vars["userid"]; !tokenData.IsServer && custodianUserId != tokenData.UserId {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "Token user id must match custodian user id or server")

	} else if newCustodialUserDetails, err := ParseNewCustodialUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if newCustodialUser, err := NewCustodialUser(newCustodialUserDetails, a.ApiConfig.Salt); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if existingCustodialUser, err := a.Store.FindUsers(newCustodialUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else if len(existingCustodialUser) != 0 {
		a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)

	} else if err := a.Store.UpsertUser(newCustodialUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else {
		permissions := clients.Permissions{"custodian": clients.Allowed, "view": clients.Allowed, "upload": clients.Allowed}
		if _, err := a.perms.SetPermissions(custodianUserId, newCustodialUser.Id, permissions); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
		} else {
			a.logMetricForUser(newCustodialUser.Id, "custodialusercreated", sessionToken, map[string]string{"server": strconv.FormatBool(tokenData.IsServer)})
			a.sendUserWithStatus(res, newCustodialUser, http.StatusCreated, tokenData.IsServer)
		}
	}
}

// status: 200
// status: 400 STATUS_INVALID_USER_DETAILS
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_FINDING_USR
// status: 500 STATUS_ERR_UPDATING_USR
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)

	} else if updateUserDetails, err := ParseUpdateUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if err := updateUserDetails.Validate(); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if originalUser, err := a.Store.FindUser(&User{Id: firstStringNotEmpty(vars["userid"], tokenData.UserId)}); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

	} else if originalUser == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "User not found")

	} else if permissions, err := a.tokenUserHasRequestedPermissions(tokenData, originalUser.Id, clients.Permissions{"root": clients.Allowed, "custodian": clients.Allowed}); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

	} else if len(permissions) == 0 {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "User does not have permissions")

	} else if (updateUserDetails.Roles != nil || updateUserDetails.EmailVerified != nil) && !tokenData.IsServer {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "User does not have permissions")

	} else if (updateUserDetails.Password != nil || updateUserDetails.TermsAccepted != nil) && permissions["root"] == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "User does not have permissions")

	} else {
		updatedUser := originalUser.DeepClone()

		// TODO: This all needs to be refactored so it can be more thoroughly tested

		if updateUserDetails.Username != nil || updateUserDetails.Emails != nil {
			dupCheck := &User{}
			if updateUserDetails.Username != nil {
				updatedUser.Username = *updateUserDetails.Username
				dupCheck.Username = updatedUser.Username
			}
			if updateUserDetails.Emails != nil {
				updatedUser.Emails = updateUserDetails.Emails
				dupCheck.Emails = updatedUser.Emails
			}

			if results, err := a.Store.FindUsers(dupCheck); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)
				return
			} else if len(results) == 1 && results[0].Id != firstStringNotEmpty(vars["userid"], tokenData.UserId) {
				//only throw an error if there is a user with a different id but with the same username/email
				a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)
				return
			} else if len(results) > 1 {
				a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)
				return
			}
		}

		if updateUserDetails.Password != nil {
			if err := updatedUser.HashPassword(*updateUserDetails.Password, a.ApiConfig.Salt); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err)
				return
			}
		}

		if updateUserDetails.Roles != nil {
			updatedUser.Roles = updateUserDetails.Roles
		}

		if updateUserDetails.TermsAccepted != nil {
			updatedUser.TermsAccepted = *updateUserDetails.TermsAccepted
		}

		if updateUserDetails.EmailVerified != nil {
			updatedUser.EmailVerified = *updateUserDetails.EmailVerified
		}

		if err := a.Store.UpsertUser(updatedUser); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err)
		} else {
			if len(originalUser.PwHash) == 0 && len(updatedUser.PwHash) != 0 {
				if err := a.removeUserPermissions(updatedUser.Id, clients.Permissions{"custodian": clients.Allowed}); err != nil {
					a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err)
				}
			}

			if updatedUser.EmailVerified && updatedUser.TermsAccepted != "" {
				if a.mailchimpManager != nil {
					if updateUserDetails.EmailVerified != nil || updateUserDetails.TermsAccepted != nil {
						a.mailchimpManager.CreateListMembershipForUser(updatedUser)
					} else {
						a.mailchimpManager.UpdateListMembershipForUser(originalUser, updatedUser)
					}
				}
			}
			a.logMetricForUser(updatedUser.Id, "userupdated", sessionToken, map[string]string{"server": strconv.FormatBool(tokenData.IsServer)})
			a.sendUser(res, updatedUser, tokenData.IsServer)
		}
	}
}

// status: 200
// status: 401 STATUS_UNAUTHORIZED
// status: 500 STATUS_ERR_FINDING_USR
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)
	} else {
		var user *User
		if userId := vars["userid"]; userId != "" {
			user = &User{Id: userId, Username: userId, Emails: []string{userId}}
		} else {
			user = &User{Id: tokenData.UserId}
		}

		if results, err := a.Store.FindUsers(user); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

		} else if len(results) == 0 {
			a.sendError(res, http.StatusNotFound, STATUS_USER_NOT_FOUND)

		} else if len(results) != 1 {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, fmt.Sprintf("Found %d users matching %#v", len(results), user))

		} else if result := results[0]; result == nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, "Found user is nil")

		} else if permissions, err := a.tokenUserHasRequestedPermissions(tokenData, result.Id, clients.Permissions{"root": clients.Allowed, "custodian": clients.Allowed}); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

		} else if permissions["root"] == nil && permissions["custodian"] == nil {
			a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED)

		} else {
			a.logMetricForUser(user.Id, "getuserinfo", sessionToken, map[string]string{"server": strconv.FormatBool(tokenData.IsServer)})
			a.sendUser(res, result, tokenData.IsServer)
		}
	}
}

func (a *Api) DeleteUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	td, err := a.authenticateSessionToken(req.Header.Get(TP_SESSION_TOKEN))

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	var id string
	if td.IsServer == true {
		id = vars["userid"]
		a.logger.Println("operating as server")
	} else {
		id = td.UserId
	}

	pw := getGivenDetail(req)["password"]

	if id != "" && pw != "" {

		var err error
		toDelete := &User{Id: id}

		if err = toDelete.HashPassword(pw, a.ApiConfig.Salt); err == nil {
			if err = a.Store.RemoveUser(toDelete); err == nil {

				if td.IsServer {
					a.logMetricForUser(id, "deleteuser", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "true"})
				} else {
					a.logMetric("deleteuser", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "false"})
				}
				//cleanup if any
				if td.IsServer == false {
					a.Store.RemoveTokenByID(req.Header.Get(TP_SESSION_TOKEN))
				}
				//all good
				res.WriteHeader(http.StatusAccepted)
				return
			}
		}
		a.logger.Println(http.StatusInternalServerError, err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		return
	}
	a.logger.Println(http.StatusForbidden, STATUS_MISSING_ID_PW)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusForbidden, STATUS_MISSING_ID_PW), http.StatusForbidden)
	return
}

// status: 200 TP_SESSION_TOKEN,
// status: 400 STATUS_MISSING_ID_PW
// status: 401 STATUS_NO_MATCH
// status: 403 STATUS_NOT_VERIFIED
// status: 500 STATUS_ERR_FINDING_USR, STATUS_ERR_UPDATING_TOKEN
func (a *Api) Login(res http.ResponseWriter, req *http.Request) {
	if user, password := unpackAuth(req.Header.Get("Authorization")); user == nil {
		a.sendError(res, http.StatusBadRequest, STATUS_MISSING_ID_PW)

	} else if results, err := a.Store.FindUsers(user); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

	} else if len(results) != 1 {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, fmt.Sprintf("Found %d users matching %#v", len(results), user))

	} else if result := results[0]; result == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, "Found user is nil")

	} else if result.IsDeleted() {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, "User is marked deleted")

	} else if !result.PasswordsMatch(password, a.ApiConfig.Salt) {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, "Passwords do not match")

	} else if !result.IsEmailVerified(a.ApiConfig.VerificationSecret) {
		a.sendError(res, http.StatusForbidden, STATUS_NOT_VERIFIED)

	} else {
		tokenData := &TokenData{DurationSecs: extractTokenDuration(req), UserId: result.Id}
		tokenConfig := TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret}
		if sessionToken, err := CreateSessionTokenAndSave(tokenData, tokenConfig, a.Store); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN, err)

		} else {
			a.logMetric("userlogin", sessionToken.ID, nil)
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			a.sendUser(res, result, false)
		}
	}
}

// status: 200 TP_SESSION_TOKEN
// status: 400 STATUS_MISSING_ID_PW
// status: 401 STATUS_PW_WRONG
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) ServerLogin(res http.ResponseWriter, req *http.Request) {

	// which server is knocking at the door and what password is it using to enter?
	server, pw := req.Header.Get(TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)
	// the expected secret is the secret that the requesting server is supposed to give to be delivered the token
	expectedSecret := ""

	// if server or password is not given we obviously have a problem
	if server == "" || pw == "" {
		a.logger.Println(http.StatusBadRequest, STATUS_MISSING_ID_PW)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_ID_PW), http.StatusBadRequest)
		return
	}

	// At this stage both given password and server are passed and known

	// What is the expected password for this specific requesting server?
	expectedSecret = a.ApiConfig.ServerSecrets[server]

	// Case specific to all Tidepool microservices that share the same secret
	// This is done in order to maintain the current behaviour where Tidepool servers use the default password
	// TODO: maintain a list of possible requesting micro-services?
	if expectedSecret == "" {
		expectedSecret = a.ApiConfig.ServerSecrets["default"]
	}

	// If no expected secret can be compared to, we have a problem and cannot continue
	if expectedSecret == "" {
		a.logger.Println(http.StatusInternalServerError, STATUS_NO_EXPECTED_PWD)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_NO_EXPECTED_PWD), http.StatusInternalServerError)
		return
	}

	// If the expected secret is the one given at the door then we can generate a token
	if pw == expectedSecret {
		//generate new token
		if sessionToken, err := CreateSessionTokenAndSave(
			&TokenData{DurationSecs: extractTokenDuration(req), UserId: server, IsServer: true},
			TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret},
			a.Store,
		); err != nil {
			// Error generating the token
			a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
			return
		} else {
			// Server is provided with the generated token
			a.logMetricAsServer("serverlogin", sessionToken.ID, nil)
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			return
		}
	}
	// If the password given at the door is wrong, we cannot generate the token
	a.logger.Println(http.StatusUnauthorized, STATUS_PW_WRONG)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
	return
}

// status: 200 TP_SESSION_TOKEN, oauthUser, oauthTarget
// status: 400 invalid_request
// status: 401 invalid_token
// status: 403 insufficient_scope
func (a *Api) oauth2Login(w http.ResponseWriter, r *http.Request) {

	//oauth is not enabled
	if a.oauth == nil {
		a.logger.Println(http.StatusServiceUnavailable, "OAuth is not enabled")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if ah := r.Header.Get("Authorization"); ah != "" {
		if len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
			if auth_token := ah[7:]; auth_token != "" {

				//check the actual token
				result, err := a.oauth.CheckToken(auth_token)
				if err != nil || result == nil {
					a.logger.Println(http.StatusUnauthorized, "oauth2Login error checking token ", err)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				//check the corresponding user
				fndUsr, errUsr := a.Store.FindUser(&User{Id: result["userId"].(string)})
				if errUsr != nil || fndUsr == nil {
					a.logger.Println(http.StatusUnauthorized, "oauth2Login error getting user ", errUsr.Error())
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				//generate token and send the response
				if sessionToken, err := CreateSessionTokenAndSave(
					&TokenData{DurationSecs: 0, UserId: result["userId"].(string), IsServer: false},
					TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret},
					a.Store,
				); err != nil {
					a.logger.Println(http.StatusUnauthorized, "oauth2Login error creating session token", err.Error())
					common.OutputJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "invalid_token"})
					return
				} else {
					//We are redirecting to the app
					w.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
					common.OutputJSON(w, http.StatusOK, map[string]interface{}{"oauthUser": fndUsr, "oauthTarget": result["authUserId"]})
					return
				}
			}
		}
		a.logger.Println(http.StatusUnauthorized, STATUS_AUTH_HEADER_INVLAID)
		common.OutputJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": STATUS_AUTH_HEADER_INVLAID})
		return
	}
	a.logger.Println(http.StatusBadRequest, STATUS_AUTH_HEADER_REQUIRED)
	common.OutputJSON(w, http.StatusBadRequest, map[string]interface{}{"error": STATUS_AUTH_HEADER_REQUIRED})
	return
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	td, err := a.authenticateSessionToken(req.Header.Get(TP_SESSION_TOKEN))

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	const two_hours_in_secs = 60 * 60 * 2

	if td.IsServer == false && td.DurationSecs > two_hours_in_secs {
		//long-duration let us know detail and keep it rolling
		a.logger.Println("long-duration token set for ", fmt.Sprint(time.Duration(td.DurationSecs)*time.Second))
	}
	//refresh
	if sessionToken, err := CreateSessionTokenAndSave(
		td,
		TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret},
		a.Store,
	); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else {
		res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
		sendModelAsRes(res, td)
		return
	}
}

// Set the longeterm duration and then process as per Login
// note: see Login for return codes
func (a *Api) LongtermLogin(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	const day_as_secs = 1 * 24 * 60 * 60

	duration := a.ApiConfig.LongTermDaysDuration * day_as_secs
	longtermkey := vars["longtermkey"]

	if longtermkey == a.ApiConfig.LongTermKey {
		a.logger.Println("token duration is ", fmt.Sprint(time.Duration(duration)*time.Second))
		req.Header.Add(TOKEN_DURATION_KEY, strconv.FormatFloat(float64(duration), 'f', -1, 64))
	} else {
		//tell us there was no match
		a.logger.Println("tried to login using the longtermkey but it didn't match the stored key")
	}

	a.Login(res, req)

	// TODO: Does not actually add the TOKEN_DURATION_KEY to the response on success (as the old unittests would imply)
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 404 STATUS_NO_TOKEN_MATCH
func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if hasServerToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret) {
		td, err := a.authenticateSessionToken(vars["token"])
		if err != nil {
			a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
			return
		}

		sendModelAsRes(res, td)
		return
	}
	a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
	return
}

// status: 200
func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	if id := req.Header.Get(TP_SESSION_TOKEN); id != "" {
		if err := a.Store.RemoveTokenByID(id); err != nil {
			//sliently fail but still log it
			a.logger.Println("Logout was unable to delete token", err.Error())
		}
	}
	//otherwise all good
	res.WriteHeader(http.StatusOK)
	return
}

// status: 200 AnonIdHashPair
func (a *Api) AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	idHashPair := NewAnonIdHashPair([]string{a.ApiConfig.Salt}, req.URL.Query())
	sendModelAsRes(res, idHashPair)
	return
}

func (a *Api) sendError(res http.ResponseWriter, statusCode int, reason string, extras ...interface{}) {
	_, file, line, ok := runtime.Caller(1)
	if ok {
		segments := strings.Split(file, "/")
		file = segments[len(segments)-1]
	} else {
		file = "???"
		line = 0
	}

	messages := make([]string, len(extras))
	for index, extra := range extras {
		messages[index] = fmt.Sprintf("%v", extra)
	}

	a.logger.Printf("%s:%d RESPONSE ERROR: [%d %s] %s", file, line, statusCode, reason, strings.Join(messages, "; "))
	sendModelAsResWithStatus(res, status.NewStatus(statusCode, reason), statusCode)
}

func (a *Api) authenticateSessionToken(sessionToken string) (*TokenData, error) {
	if sessionToken == "" {
		return nil, errors.New("Session token is empty")
	} else if tokenData, err := UnpackSessionTokenAndVerify(sessionToken, a.ApiConfig.Secret); err != nil {
		return nil, err
	} else if _, err := a.Store.FindTokenByID(sessionToken); err != nil {
		return nil, err
	} else {
		return tokenData, nil
	}
}

func (a *Api) tokenUserHasRequestedPermissions(tokenData *TokenData, groupId string, requestedPermissions clients.Permissions) (clients.Permissions, error) {
	if tokenData.IsServer {
		return requestedPermissions, nil
	} else if tokenData.UserId == groupId {
		return requestedPermissions, nil
	} else if actualPermissions, err := a.perms.UserInGroup(tokenData.UserId, groupId); err != nil {
		return clients.Permissions{}, err
	} else {
		finalPermissions := make(clients.Permissions, 0)
		for permission, _ := range requestedPermissions {
			if reflect.DeepEqual(requestedPermissions[permission], actualPermissions[permission]) {
				finalPermissions[permission] = requestedPermissions[permission]
			}
		}
		return finalPermissions, nil
	}
}

func (a *Api) removeUserPermissions(groupId string, removePermissions clients.Permissions) error {
	if originalUserPermissions, err := a.perms.UsersInGroup(groupId); err != nil {
		return err
	} else {
		for userId, originalPermissions := range originalUserPermissions {
			finalPermissions := make(clients.Permissions)
			for name, value := range originalPermissions {
				if _, ok := removePermissions[name]; !ok {
					finalPermissions[name] = value
				}
			}
			if len(finalPermissions) != len(originalPermissions) {
				if _, err := a.perms.SetPermissions(userId, groupId, finalPermissions); err != nil {
					return err
				}
			}
		}
		return nil
	}
}
