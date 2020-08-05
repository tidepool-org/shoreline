package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tidepool-org/shoreline/keycloak"
	"log"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/highwater"
	"github.com/tidepool-org/go-common/clients/status"
	"github.com/tidepool-org/shoreline/user/marketo"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	failedMarketoUploadCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tidepool_shoreline_failed_marketo_upload_total",
		Help: "The total number of failures to connect to marketo due to errors",
	})
	statusCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tidepool_shoreline_failed_status_count",
		Help: "The number of errors for each status code and status reason.",
	}, []string{"status_reason", "status_code"})
)

type (
	Api struct {
		Store          Storage
		ApiConfig      ApiConfig
		metrics        highwater.Client
		perms          clients.Gatekeeper
		logger         *log.Logger
		marketoManager marketo.Manager
		keycloakClient keycloak.Client
	}
	ApiConfig struct {
		ClientID             string         `json:"clientId"`
		ClientSecret         string         `json:"clientSecret"`
		KeycloakBaseUrl      string         `json:"keycloakBaseUrl"`
		ServerSecret         string         `json:"serverSercret"`
		TokenConfigs         []TokenConfig  `json:"tokenConfigs"` // the first token config is used for encoding new tokens
		LongTermKey          string         `json:"longTermKey"`
		LongTermDaysDuration int            `json:"longTermDaysDuration"`
		Salt                 string         `json:"salt"`
		VerificationSecret   string         `json:"verificationSecret"`
		ClinicDemoUserID     string         `json:"clinicDemoUserId"`
		Marketo              marketo.Config `json:"marketo"`
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
	STATUS_AUTH_HEADER_INVALID   = "Authorization header is invalid"
	STATUS_GETSTATUS_ERR         = "Error checking service status"
	STATUS_UNAUTHORIZED          = "Not authorized for requested operation"
	STATUS_NO_QUERY              = "A query must be specified"
	STATUS_PARAMETER_UNKNOWN     = "Unknown query parameter"
	STATUS_ONE_QUERY_PARAM       = "Only one query parameter is allowed"
	STATUS_INVALID_ROLE          = "The role specified is invalid"
)

func InitApi(cfg ApiConfig, logger *log.Logger, store Storage, metrics highwater.Client, manager marketo.Manager, keycloakClient keycloak.Client) *Api {
	return &Api{
		Store:          store,
		ApiConfig:      cfg,
		metrics:        metrics,
		logger:         logger,
		marketoManager: manager,
		keycloakClient: keycloakClient,
	}
}

func (a *Api) AttachPerms(perms clients.Gatekeeper) {
	a.perms = perms
}

func (a *Api) SetHandlers(prefix string, rtr *mux.Router) {
	rtr.Handle("/metrics", promhttp.Handler())

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

	rtr.HandleFunc("/serverlogin", a.ServerLogin).Methods("POST")

	rtr.Handle("/token/{token}", varsHandler(a.ServerCheckToken)).Methods("GET")

	rtr.HandleFunc("/logout", a.Logout).Methods("POST")

	rtr.HandleFunc("/private", a.AnonymousIdHashPair).Methods("GET")

	rtr.Handle("/migrate/{username}", varsHandler(a.GetUserForMigration)).Methods("GET")
	rtr.Handle("/migrate/{username}", varsHandler(a.CheckUserPassword)).Methods("POST")
}

func (h varsHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	h(res, req, vars)
}

func (a *Api) GetStatus(res http.ResponseWriter, req *http.Request) {
	if err := a.Store.WithContext(req.Context()).Ping(); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_GETSTATUS_ERR, err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(err.Error()))
		return
	}
	res.WriteHeader(http.StatusOK)
	fmt.Fprintf(res, "OK")
	return
}

// GetUsers returns all users
// status: 200
// status: 400 STATUS_NO_QUERY, STATUS_PARAMETER_UNKNOWN
// status: 401 STATUS_SERVER_TOKEN_REQUIRED
// status: 500 STATUS_ERR_FINDING_USR
func (a *Api) GetUsers(res http.ResponseWriter, req *http.Request) {
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)

	} else if !tokenData.IsServer {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED)

	} else if len(req.URL.Query()) == 0 {
		a.sendError(res, http.StatusBadRequest, STATUS_NO_QUERY)

	} else if role := req.URL.Query().Get("role"); role != "" && !IsValidRole(role) {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_ROLE)

	} else if userIds := strings.Split(req.URL.Query().Get("id"), ","); len(userIds[0]) > 0 && role != "" {
		a.sendError(res, http.StatusBadRequest, STATUS_ONE_QUERY_PARAM)

	} else {
		var users []*User
		switch {
		case role != "":
			if users, err = a.Store.WithContext(req.Context()).FindUsersByRole(role); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
			}
		case len(userIds[0]) > 0:
			if users, err = a.Store.WithContext(req.Context()).FindUsersWithIds(userIds); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
			}
		default:
			a.sendError(res, http.StatusBadRequest, STATUS_PARAMETER_UNKNOWN)
		}
		a.logMetric("getusers", sessionToken, map[string]string{"server": strconv.FormatBool(tokenData.IsServer)})
		a.sendUsers(res, users, tokenData.IsServer)
	}
}

// CreateUser creates a new user
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
	} else if existingUser, err := a.Store.WithContext(req.Context()).FindUsers(newUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else if len(existingUser) != 0 {
		a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)

	} else if err := a.Store.WithContext(req.Context()).UpsertUser(newUser); err != nil {
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
		tokenConfig := a.ApiConfig.TokenConfigs[0]
		if sessionToken, err := CreateSessionTokenAndSave(&tokenData, tokenConfig, a.Store.WithContext(req.Context())); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err)
		} else {
			a.logMetricForUser(newUser.Id, "usercreated", sessionToken.ID, map[string]string{"server": "false"})
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			a.sendUserWithStatus(res, newUser, http.StatusCreated, false)
		}
	}
}

// CreateCustodialUser creates a new custodial user
// status: 201 User
// status: 400 STATUS_MISSING_USR_DETAILS
// status: 401 STATUS_UNAUTHORIZED
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) CreateCustodialUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	sessionToken := req.Header.Get(TP_SESSION_TOKEN)

	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)

	} else if custodianUserID := vars["userid"]; !tokenData.IsServer && custodianUserID != tokenData.UserId {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "Token user id must match custodian user id or server")

	} else if newCustodialUserDetails, err := ParseNewCustodialUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if newCustodialUser, err := NewCustodialUser(newCustodialUserDetails, a.ApiConfig.Salt); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if existingCustodialUser, err := a.Store.WithContext(req.Context()).FindUsers(newCustodialUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else if len(existingCustodialUser) != 0 {
		a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)

	} else if err := a.Store.WithContext(req.Context()).UpsertUser(newCustodialUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else {
		permissions := clients.Permissions{"custodian": clients.Allowed, "view": clients.Allowed, "upload": clients.Allowed}
		if _, err := a.perms.SetPermissions(custodianUserID, newCustodialUser.Id, permissions); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
		} else {
			a.logMetricForUser(newCustodialUser.Id, "custodialusercreated", sessionToken, map[string]string{"server": strconv.FormatBool(tokenData.IsServer)})
			a.sendUserWithStatus(res, newCustodialUser, http.StatusCreated, tokenData.IsServer)
		}
	}
}

// UpdateUser updates a user
// status: 200
// status: 400 STATUS_INVALID_USER_DETAILS
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_FINDING_USR
// status: 500 STATUS_ERR_UPDATING_USR
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	a.logger.Printf("UpdateUser %v", req)
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)

	} else if updateUserDetails, err := ParseUpdateUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if err := updateUserDetails.Validate(); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if originalUser, err := a.Store.WithContext(req.Context()).FindUser(&User{Id: firstStringNotEmpty(vars["userid"], tokenData.UserId)}); err != nil {
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

			if results, err := a.Store.WithContext(req.Context()).FindUsers(dupCheck); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)
				return
			} else if len(results) > 0 {
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

		if err := a.Store.WithContext(req.Context()).UpsertUser(updatedUser); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err)
		} else {
			if len(originalUser.PwHash) == 0 && len(updatedUser.PwHash) != 0 {
				if err := a.removeUserPermissions(updatedUser.Id, clients.Permissions{"custodian": clients.Allowed}); err != nil {
					a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err)
				}
			}

			if updatedUser.EmailVerified && updatedUser.TermsAccepted != "" {
				if a.marketoManager != nil && a.marketoManager.IsAvailable() {
					if updateUserDetails.EmailVerified != nil || updateUserDetails.TermsAccepted != nil {
						a.marketoManager.CreateListMembershipForUser(updatedUser)
					} else {
						a.marketoManager.UpdateListMembershipForUser(originalUser, updatedUser)
					}
				} else {
					failedMarketoUploadCount.Inc()
				}
			}
			a.logMetricForUser(updatedUser.Id, "userupdated", sessionToken, map[string]string{"server": strconv.FormatBool(tokenData.IsServer)})
			a.sendUser(res, updatedUser, tokenData.IsServer)
		}
	}
}

// GetUserInfo returns user info
// status: 200
// status: 401 STATUS_UNAUTHORIZED
// status: 500 STATUS_ERR_FINDING_USR
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)
	} else {
		var user *User
		if userID := vars["userid"]; userID != "" {
			user = &User{Id: userID, Username: userID, Emails: []string{userID}}
		} else {
			user = &User{Id: tokenData.UserId}
		}

		if results, err := a.Store.WithContext(req.Context()).FindUsers(user); err != nil {
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

	td, err := a.authenticateSessionToken(req.Context(), req.Header.Get(TP_SESSION_TOKEN))

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
			if err = a.Store.WithContext(req.Context()).RemoveUser(toDelete); err == nil {

				if td.IsServer {
					a.logMetricForUser(id, "deleteuser", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "true"})
				} else {
					a.logMetric("deleteuser", req.Header.Get(TP_SESSION_TOKEN), map[string]string{"server": "false"})
				}
				//cleanup if any
				if td.IsServer == false {
					a.Store.WithContext(req.Context()).RemoveTokenByID(req.Header.Get(TP_SESSION_TOKEN))
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
	} else if token, err := a.keycloakClient.Login(req.Context(), user.Username, password); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)
	} else if tidepoolSessionToken, err := keycloak.CreateBackwardCompatibleToken(token); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)
	} else {
		res.Header().Set(TP_SESSION_TOKEN, tidepoolSessionToken)
		a.sendUser(res, user, false)
	}
}

// status: 200 TP_SESSION_TOKEN
// status: 400 STATUS_MISSING_ID_PW
// status: 401 STATUS_PW_WRONG
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) ServerLogin(res http.ResponseWriter, req *http.Request) {

	server, pw := req.Header.Get(TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)

	if server == "" || pw == "" {
		a.logger.Println(http.StatusBadRequest, STATUS_MISSING_ID_PW)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_ID_PW), http.StatusBadRequest)
		return
	}
	if pw == a.ApiConfig.ServerSecret {
		//generate new token
		if sessionToken, err := CreateSessionTokenAndSave(
			&TokenData{DurationSecs: extractTokenDuration(req), UserId: server, IsServer: true},
			a.ApiConfig.TokenConfigs[0],
			a.Store.WithContext(req.Context()),
		); err != nil {
			a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
			return
		} else {
			a.logMetricAsServer("serverlogin", sessionToken.ID, nil)
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			return
		}
	}
	a.logger.Println(http.StatusUnauthorized, STATUS_PW_WRONG)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
	return
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	td, err := a.authenticateSessionToken(req.Context(), req.Header.Get(TP_SESSION_TOKEN))

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	const two_hours_in_secs = 60 * 60 * 2

	if td.IsServer == false && td.DurationSecs > two_hours_in_secs {
		//long-duration let us know detail and keep it rolling
		//a.logger.Println("long-duration token set for ", fmt.Sprint(time.Duration(td.DurationSecs)*time.Second))
	}
	//refresh
	if sessionToken, err := CreateSessionTokenAndSave(
		td,
		a.ApiConfig.TokenConfigs[0],
		a.Store.WithContext(req.Context()),
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

	if hasServerToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.TokenConfigs...) {
		td, err := a.authenticateSessionToken(req.Context(), vars["token"])
		if err != nil {
			a.logger.Printf("failed request: %v", req)
			a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
			return
		}

		sendModelAsRes(res, td)
		return
	}
	a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN)
	a.logger.Printf("header session token: %v", req.Header.Get(TP_SESSION_TOKEN))
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
	return
}

// status: 200
func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	if id := req.Header.Get(TP_SESSION_TOKEN); id != "" {
		if keycloak.IsKeycloakToken(id) {
			if token, err := keycloak.UnpackBackwardCompatibleToken(id); err != nil {
				a.logger.Println("Unable to unpack token", err.Error())
			} else if err := a.keycloakClient.RevokeToken(req.Context(), token); err != nil {
				a.logger.Println("Unable to logout from keycloak", err.Error())
			}
		} else if err := a.Store.WithContext(req.Context()).RemoveTokenByID(id); err != nil {
			//silently fail but still log it
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

// Returns the user profile in the expected format for migration
func (a *Api) GetUserForMigration(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)
	} else if !tokenData.IsServer {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED)
	}

	username, ok := vars["username"]
	if !ok {
		res.WriteHeader(http.StatusBadRequest)
		return
	}

	users, err := a.Store.WithContext(req.Context()).FindUsers(&User{
		Username: username,
	})
	if err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
		return
	} else if len(users) != 1 || users[0].IsDeleted() {
		a.sendError(res, http.StatusNotFound, STATUS_USER_NOT_FOUND)
		return
	}

	user := users[0]
	keycloakUser := &keycloak.User{
		Username:      user.Username,
		Email:         user.Email(),
		Enabled:       true,
		EmailVerified: users[0].EmailVerified,
		Roles:         users[0].Roles,
		Attributes: keycloak.UserAttributes{
			TermsAccepted: []string{fmt.Sprintf("%v", users[0].TermsAccepted)},
		},
	}

	sendModelAsRes(res, keycloakUser)
	return
}

// status: 200 if a user with the required password exists
func (a *Api) CheckUserPassword(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	username, ok := vars["username"]
	request := keycloak.CheckPasswordRequest{}
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	}

	if !ok || !a.userWithPasswordExists(req.Context(), username, request.Password) {
		a.sendError(res, http.StatusNotFound, STATUS_USER_NOT_FOUND)
		return
	}

	res.WriteHeader(http.StatusOK)
}

func (a *Api) userWithPasswordExists(ctx context.Context, username, password string) bool {
	users, err := a.Store.WithContext(ctx).FindUsers(&User{
		Username: username,
	})

	return err == nil &&
		len(users) == 1 &&
		!users[0].IsDeleted() &&
		users[0].PasswordsMatch(password, a.ApiConfig.Salt)
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

	statusCount.WithLabelValues(reason, strconv.Itoa(statusCode)).Inc()

	a.logger.Printf("%s:%d RESPONSE ERROR: [%d %s] %s", file, line, statusCode, reason, strings.Join(messages, "; "))
	sendModelAsResWithStatus(res, status.NewStatus(statusCode, reason), statusCode)
}

func (a *Api) authenticateSessionToken(ctx context.Context, sessionToken string) (*TokenData, error) {
	if sessionToken == "" {
		return nil, errors.New("Session token is empty")
	} else if tokenData, err := UnpackSessionTokenAndVerify(sessionToken, a.ApiConfig.TokenConfigs...); err != nil {
		return nil, err
	} else if _, err := a.Store.WithContext(ctx).FindTokenByID(sessionToken); err != nil {
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
		for permission := range requestedPermissions {
			if reflect.DeepEqual(requestedPermissions[permission], actualPermissions[permission]) {
				finalPermissions[permission] = requestedPermissions[permission]
			}
		}
		return finalPermissions, nil
	}
}

func (a *Api) removeUserPermissions(groupId string, removePermissions clients.Permissions) error {
	originalUserPermissions, err := a.perms.UsersInGroup(groupId)
	if err != nil {
		return err
	}
	for userID, originalPermissions := range originalUserPermissions {
		finalPermissions := make(clients.Permissions)
		for name, value := range originalPermissions {
			if _, ok := removePermissions[name]; !ok {
				finalPermissions[name] = value
			}
		}
		if len(finalPermissions) != len(originalPermissions) {
			if _, err := a.perms.SetPermissions(userID, groupId, finalPermissions); err != nil {
				return err
			}
		}
	}
	return nil
}
