package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	api "github.com/tidepool-org/clinic/client"
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
	"github.com/tidepool-org/go-common/clients/status"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	statusCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tidepool_shoreline_failed_status_count",
		Help: "The number of errors for each status code and status reason.",
	}, []string{"status_reason", "status_code"})
)

type (
	Api struct {
		Store              Storage
		ApiConfig          ApiConfig
		clinic             api.ClientWithResponsesInterface
		perms              clients.Gatekeeper
		logger             *log.Logger
		keycloakClient     keycloak.Client
		seagull            clients.Seagull
		userEventsNotifier EventsNotifier
		sessionToken       *SessionToken
		tokenAuthenticator TokenAuthenticator
	}
	ApiConfig struct {
		ServerSecret         string           `json:"serverSercret"`
		TokenConfigs         []TokenConfig    `json:"tokenConfigs"` // the first token config is used for encoding new tokens
		LongTermKey          string           `json:"longTermKey"`
		LongTermDaysDuration int              `json:"longTermDaysDuration"`
		Salt                 string           `json:"salt"`
		VerificationSecret   string           `json:"verificationSecret"`
		ClinicDemoUserID     string           `json:"clinicDemoUserId"`
		MigrationSecret      string           `json:"migrationSecret"`
		TokenCacheConfig     TokenCacheConfig `json:"tokenCacheConfig"`
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
	STATUS_INVALID_QUERY_PARAM   = "Invalid query parameter: "
	STATUS_INVALID_ROLE          = "The role specified is invalid"
)

func InitApi(cfg ApiConfig, logger *log.Logger, store Storage, keycloakClient keycloak.Client, userEventsNotifier EventsNotifier, seagull clients.Seagull, clinic api.ClientWithResponsesInterface) *Api {
	tokenAuthenticator := NewTokenAuthenticator(keycloakClient, store, cfg.TokenConfigs)
	if cfg.TokenCacheConfig.Enabled {
		tokenAuthenticator = NewCachingTokenAuthenticator(&cfg.TokenCacheConfig, tokenAuthenticator)
	}

	return &Api{
		Store:              store,
		ApiConfig:          cfg,
		logger:             logger,
		keycloakClient:     keycloakClient,
		userEventsNotifier: userEventsNotifier,
		seagull:            seagull,
		clinic:             clinic,
		tokenAuthenticator: tokenAuthenticator,
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
	rtr.Handle("/v1/users/{userid}", varsHandler(a.GetUserInfo)).Methods("GET")

	rtr.HandleFunc("/user", a.CreateUser).Methods("POST")
	rtr.Handle("/user", varsHandler(a.UpdateUser)).Methods("PUT")
	rtr.Handle("/user/{userid}", varsHandler(a.UpdateUser)).Methods("PUT")
	rtr.Handle("/user/{userid}", varsHandler(a.DeleteUser)).Methods("DELETE")
	rtr.Handle("/user/{userid}/sessions", varsHandler(a.DeleteUserSessions)).Methods("DELETE")

	rtr.Handle("/user/{userid}/user", varsHandler(a.CreateCustodialUser)).Methods("POST")
	rtr.Handle("/v1/clinics/{clinicid}/users", varsHandler(a.CreateClinicCustodialUser)).Methods("POST")

	rtr.HandleFunc("/login", a.Login).Methods("POST")
	rtr.HandleFunc("/login", a.RefreshSession).Methods("GET")
	rtr.Handle("/login/{longtermkey}", varsHandler(a.LongtermLogin)).Methods("POST")

	rtr.HandleFunc("/serverlogin", a.ServerLogin).Methods("POST")

	rtr.Handle("/token/{token}", varsHandler(a.ServerCheckToken)).Methods("GET")
	rtr.HandleFunc("/token", a.CheckToken).Methods("GET")

	rtr.HandleFunc("/logout", a.Logout).Methods("POST")

	rtr.HandleFunc("/private", a.AnonymousIdHashPair).Methods("GET")

	rtr.Handle("/migrate/{username}", varsHandler(a.GetUserForMigration)).Methods("GET")
	rtr.Handle("/migrate/{userid}", varsHandler(a.CheckUserPassword)).Methods("POST")
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
	if tokenData, err := a.tokenAuthenticator.Authenticate(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)

	} else if !tokenData.IsServer {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED)

	} else if len(req.URL.Query()) == 0 {
		a.sendError(res, http.StatusBadRequest, STATUS_NO_QUERY)

	} else if role := req.URL.Query().Get("role"); role != "" && !IsValidRole(role) {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_ROLE)

	} else if userIds := strings.Split(req.URL.Query().Get("id"), ","); len(userIds[0]) > 0 && role != "" {
		a.sendError(res, http.StatusBadRequest, STATUS_ONE_QUERY_PARAM)

	} else if createdFrom, dateErr := ParseAndValidateDateParam(req.URL.Query().Get("createdFrom")); dateErr != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_QUERY_PARAM+"createdFrom")

	} else if createdTo, dateErr := ParseAndValidateDateParam(req.URL.Query().Get("createdTo")); dateErr != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_QUERY_PARAM+"createdTo")

	} else {
		var users []*User
		switch {
		case role != "":

			switch {
			case !createdFrom.IsZero() || !createdTo.IsZero():
				if users, err = a.Store.WithContext(req.Context()).FindUsersByRoleAndDate(role, createdFrom, createdTo); err != nil {
					a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
				}
			default:
				if users, err = a.Store.WithContext(req.Context()).FindUsersByRole(role); err != nil {
					a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
				}
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
	} else if existingUser, err := a.Store.WithContext(req.Context()).FindUser(&User{Emails: newUser.Emails}); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
	} else if existingUser != nil {
		// This check is necessary because we want to prevent duplicates in both mongo and keycloak
		a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)
	} else {
		isEmailVerified := newUser.IsEmailVerified(a.ApiConfig.VerificationSecret)
		if isEmailVerified {
			newUserDetails.EmailVerified = isEmailVerified
			a.logger.Printf("User email %s contains %v, setting email verified to %v", newUser.Username, a.ApiConfig.VerificationSecret, newUser.EmailVerified)
		}

		newUser, err = a.Store.WithContext(req.Context()).CreateUser(newUserDetails)
		if err != nil {
			if err == ErrUserConflict {
				a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)
			} else {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
			}
			return
		}

		if newUser.IsClinic() {
			if a.ApiConfig.ClinicDemoUserID != "" {
				if _, err := a.perms.SetPermissions(newUser.Id, a.ApiConfig.ClinicDemoUserID, clients.Permissions{"view": clients.Allowed}); err != nil {
					a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
					return
				}
			}
		}

		token, err := a.keycloakClient.Login(req.Context(), *newUserDetails.Username, *newUserDetails.Password)
		if err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err)
			return
		}
		tidepoolSessionToken, err := keycloak.CreateBackwardCompatibleToken(token)
		if err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err)
			return
		}

		res.Header().Set(TP_SESSION_TOKEN, tidepoolSessionToken)
		a.sendUserWithStatus(res, newUser, http.StatusCreated, false)
	}
}

// CreateCustodialUser creates a new custodial user
// status: 201 User
// status: 400 STATUS_MISSING_USR_DETAILS
// status: 401 STATUS_UNAUTHORIZED
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) CreateCustodialUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	token := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.tokenAuthenticator.Authenticate(req.Context(), token); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)
	} else if custodianUserID := vars["userid"]; !tokenData.IsServer && custodianUserID != tokenData.UserId {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "Token user id must match custodian user id or server")
	} else if newCustodialUser, err := a.createCustodialUserAccount(res, req); err != nil {
		// response was already sent
		return
	} else {
		permissions := clients.Permissions{"custodian": clients.Allowed, "view": clients.Allowed, "upload": clients.Allowed}
		if _, err := a.perms.SetPermissions(custodianUserID, newCustodialUser.Id, permissions); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
		} else {
			a.sendUserWithStatus(res, newCustodialUser, http.StatusCreated, tokenData.IsServer)
		}
	}
}

// CreateCustodialUser creates a new custodial user where the custodian is a clinic
// status: 201 User
// status: 400 STATUS_MISSING_USR_DETAILS
// status: 401 STATUS_UNAUTHORIZED
// status: 409 STATUS_USR_ALREADY_EXISTS
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) CreateClinicCustodialUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	token := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.tokenAuthenticator.Authenticate(req.Context(), token); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)
	} else if !tokenData.IsServer {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "Token user id must match custodian user id or server")
	} else if newCustodialUser, err := a.createCustodialUserAccount(res, req); err != nil {
		return
	} else {
		a.sendUserWithStatus(res, newCustodialUser, http.StatusCreated, tokenData.IsServer)
	}
}

func (a *Api) createCustodialUserAccount(res http.ResponseWriter, req *http.Request) (*User, error) {
	if newCustodialUserDetails, err := ParseNewCustodialUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)
		return nil, err
	} else if err := newCustodialUserDetails.Validate(); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)
		return nil, err
	} else if newCustodialUser, err := NewCustodialUser(newCustodialUserDetails, a.ApiConfig.Salt); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)
		return nil, err
	} else if existingUsers, err := a.Store.WithContext(req.Context()).FindUsers(newCustodialUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
		return nil, err
	} else if len(existingUsers) > 0 {
		a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)
		return nil, errors.New(STATUS_USR_ALREADY_EXISTS)
	} else if newUserDetails, err := NewUserDetailsFromCustodialUserDetails(newCustodialUserDetails); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)
		return nil, err
	} else if user, err := a.Store.WithContext(req.Context()).CreateUser(newUserDetails); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
		return nil, err
	} else {
		return user, nil
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
	token := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.tokenAuthenticator.Authenticate(req.Context(), token); err != nil {
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
		if updateUserDetails.Password != nil {
			hash, err := GeneratePasswordHash(originalUser.Id, *updateUserDetails.Password, a.ApiConfig.Salt)
			if err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err)
				return
			}
			updateUserDetails.HashedPassword = &hash
		}
		if updatedUser, err := a.Store.WithContext(req.Context()).UpdateUser(originalUser, updateUserDetails); err != nil {
			if err == ErrEmailConflict {
				a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS)
			} else {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err)
			}
		} else {
			var errs []error
			if len(originalUser.PwHash) == 0 && len(updatedUser.PwHash) != 0 {
				if e := a.removeCustodianPermissionsForUser(updatedUser.Id); e != nil {
					a.logger.Println(http.StatusInternalServerError, e.Error())
					errs = append(errs, e)
				}
			}

			if e := a.userEventsNotifier.NotifyUserUpdated(req.Context(), *originalUser, *updatedUser); e != nil {
				a.logger.Println(http.StatusInternalServerError, e.Error())
				errs = append(errs, e)
			}

			if len(errs) > 0 {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, errs)
				return
			}

			a.sendUser(res, updatedUser, tokenData.IsServer)
		}
	}
}

// GetUserInfo returns user info
// status: 200
// status: 401 STATUS_UNAUTHORIZED
// status: 500 STATUS_ERR_FINDING_USR
func (a *Api) GetUserInfo(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	token := req.Header.Get(TP_SESSION_TOKEN)
	tokenData, err := a.tokenAuthenticator.Authenticate(req.Context(), token)
	if err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)
		return
	}

	userId := vars["userid"]
	if userId == "" {
		userId = tokenData.UserId
	}

	userFilter := &User{}
	if IsValidUserID(userId) {
		userFilter.Id = userId
	} else {
		userFilter.Emails = []string{userId}
	}

	if user, err := a.Store.WithContext(req.Context()).FindUser(userFilter); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

	} else if user == nil {
		a.sendError(res, http.StatusNotFound, STATUS_USER_NOT_FOUND, err)

	} else if permissions, err := a.tokenUserHasRequestedPermissions(tokenData, user.Id, clients.Permissions{"root": clients.Allowed, "custodian": clients.Allowed}); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

	} else if permissions["root"] == nil && permissions["custodian"] == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED)

	} else {
		a.sendUser(res, user, tokenData.IsServer)
	}
}

func (a *Api) DeleteUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	ctx := req.Context()
	userID := vars["userid"]

	tokenData, err := a.tokenAuthenticator.Authenticate(ctx, req.Header.Get(TP_SESSION_TOKEN))
	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	var requiresPassword bool
	if !tokenData.IsServer {
		ownerOrCustodian := clients.Permissions{"root": clients.Allowed, "custodian": clients.Allowed}
		if permissions, err := a.tokenUserHasRequestedPermissions(tokenData, userID, ownerOrCustodian); err != nil {
			a.logger.Println(http.StatusInternalServerError, err.Error())
			res.WriteHeader(http.StatusInternalServerError)
			return
		} else if permissions["root"] != nil {
			requiresPassword = true
		} else if permissions["custodian"] != nil {
			requiresPassword = false
		} else {
			res.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	user, err := a.Store.WithContext(ctx).FindUser(&User{Id: userID})
	if err != nil {
		a.logger.Println(http.StatusInternalServerError, err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	if user.IsClinic() {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	if requiresPassword {
		password := getGivenDetail(req)["password"]
		// The only way to check the password with keycloak is to login with the credentials
		if _, err := a.keycloakClient.Login(req.Context(), user.Username, password); err != nil {
			a.logger.Println(http.StatusForbidden, STATUS_MISSING_ID_PW, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusForbidden, STATUS_MISSING_ID_PW), http.StatusForbidden)
			return
		}
	}

	profile, err := a.getUserProfile(ctx, userID)
	if err != nil {
		a.logger.Println(http.StatusInternalServerError, err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := a.userEventsNotifier.NotifyUserDeleted(ctx, *user, *profile); err != nil {
		a.logger.Println(http.StatusInternalServerError, err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.WriteHeader(http.StatusNoContent)
	return
}

func (a *Api) getUserProfile(ctx context.Context, userID string) (*Profile, error) {
	if a.sessionToken == nil || a.sessionToken.ExpiresAt.Before(time.Now()) {
		var err error
		duration := int64(60 * 60 * 30)
		tokenData := &TokenData{DurationSecs: duration, UserId: "shoreline", IsServer: true}
		a.sessionToken, err = CreateSessionTokenAndSave(tokenData, a.ApiConfig.TokenConfigs[0], a.Store.WithContext(ctx))
		if err != nil {
			return nil, err
		}
	}

	profile := &Profile{}
	if err := a.seagull.GetCollection(userID, "profile", a.sessionToken.ID, profile); err != nil {
		return nil, err
	}
	return profile, nil
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
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, err)
	} else if tidepoolSessionToken, err := keycloak.CreateBackwardCompatibleToken(token); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN, err)
	} else if introspectionResult, err := a.keycloakClient.IntrospectToken(req.Context(), *token); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN, err)
	} else if !introspectionResult.EmailVerified {
		a.sendError(res, http.StatusForbidden, STATUS_NOT_VERIFIED)
	} else if user, err := a.Store.FindUser(&User{Id: introspectionResult.Subject}); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_ERR_FINDING_USR, err)
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
	clientId, clientSecret := req.Header.Get(TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)
	if clientId == "" || clientSecret == "" {
		a.logger.Println(http.StatusBadRequest, STATUS_MISSING_ID_PW)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_MISSING_ID_PW), http.StatusBadRequest)
		return
	}

	if clientSecret != a.ApiConfig.ServerSecret {
		a.logger.Println(http.StatusUnauthorized, STATUS_PW_WRONG)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
		return
	}

	oauthToken, err := a.keycloakClient.GetBackendServiceToken(req.Context())
	if err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	}

	res.Header().Set(TP_SESSION_TOKEN, oauthToken.AccessToken)
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {
	token := req.Header.Get(TP_SESSION_TOKEN)
	if keycloak.IsKeycloakBackwardCompatibleToken(token) {
		a.RefreshKeycloakSession(res, req)
		return
	} else {
		a.RefreshLegacySession(res, req)
		return
	}
}

func (a *Api) RefreshKeycloakSession(res http.ResponseWriter, req *http.Request) {
	token := req.Header.Get(TP_SESSION_TOKEN)
	var tokenData *TokenData
	if !keycloak.IsKeycloakBackwardCompatibleToken(token) {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	}
	oauthToken, err := keycloak.UnpackBackwardCompatibleToken(token)
	if err == nil {
		// Force token refresh if the token is not yet expired
		oauthToken.Expiry = time.Now()
		oauthToken, err = a.keycloakClient.RefreshToken(req.Context(), *oauthToken)
		if err != nil {
			a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
			return
		}
		if token, err = keycloak.CreateBackwardCompatibleToken(oauthToken); err == nil {
			tokenData, err = a.tokenAuthenticator.AuthenticateKeycloakToken(req.Context(), token)
		}
	}
	if err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	}

	res.Header().Set(TP_SESSION_TOKEN, token)
	sendModelAsRes(res, tokenData)
	return
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
// status: 500 STATUS_ERR_GENERATING_TOKEN
func (a *Api) RefreshLegacySession(res http.ResponseWriter, req *http.Request) {

	td, err := a.tokenAuthenticator.Authenticate(req.Context(), req.Header.Get(TP_SESSION_TOKEN))

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
	ctx := req.Context()
	// Check whether the request is made by a server authorized for using this endpoint
	serverToken := req.Header.Get(TP_SESSION_TOKEN)
	if serverToken == "" {
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
		return
	}

	if tokenData, err := a.tokenAuthenticator.Authenticate(ctx, serverToken); err != nil {
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else if !tokenData.IsServer {
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
		return
	}

	// Return the token data
	userToken := vars["token"]
	tokenData, err := a.tokenAuthenticator.Authenticate(ctx, userToken)
	if err != nil {
		a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN, err)
		a.logger.Printf("header session token: %v", userToken)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
		return
	}

	sendModelAsRes(res, tokenData)
	return
}

// status: 200 TP_SESSION_TOKEN, TokenData
// status: 401 STATUS_NO_TOKEN
func (a *Api) CheckToken(res http.ResponseWriter, req *http.Request) {
	token := req.Header.Get(TP_SESSION_TOKEN)
	td, err := a.tokenAuthenticator.Authenticate(req.Context(), token)
	if err != nil {
		a.logger.Printf("failed request: %v", req)
		a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
		return
	}

	sendModelAsRes(res, td)
	return
}

// status: 200
func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	if id := req.Header.Get(TP_SESSION_TOKEN); id != "" {
		if keycloak.IsKeycloakBackwardCompatibleToken(id) {
			if token, err := keycloak.UnpackBackwardCompatibleToken(id); err != nil {
				a.logger.Println("Unable to unpack token", err.Error())
			} else if err := a.keycloakClient.RevokeToken(req.Context(), *token); err != nil {
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

// status: 200
func (a *Api) DeleteUserSessions(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	userId := vars["userid"]
	token := req.Header.Get(TP_SESSION_TOKEN)

	if td, err := a.tokenAuthenticator.Authenticate(req.Context(), token); err != nil || !td.IsServer {
		a.logger.Println(http.StatusUnauthorized, STATUS_NO_TOKEN, err)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
		return
	}

	if err := a.Store.RemoveTokensForUser(userId); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	}

	res.WriteHeader(http.StatusNoContent)
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
	if a.ApiConfig.MigrationSecret == "" || req.Header.Get("authorization") != fmt.Sprintf("Bearer %v", a.ApiConfig.MigrationSecret) {
		res.WriteHeader(http.StatusUnauthorized)
		return
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
	} else if len(users) != 1 || users[0].IsDeleted() || !users[0].EmailVerified {
		a.sendError(res, http.StatusNotFound, STATUS_USER_NOT_FOUND)
		return
	}

	user := users[0]
	keycloakUser := user.ToKeycloakUser()

	sendModelAsRes(res, keycloakUser)
	return
}

type CheckPassword struct {
	Password string `json:"password"`
}

// status: 200 if a user with the required password exists
func (a *Api) CheckUserPassword(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	userid, ok := vars["userid"]
	request := CheckPassword{}
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)
		return
	}

	if !ok || !a.userWithPasswordExists(req.Context(), userid, request.Password) {
		a.sendError(res, http.StatusNotFound, STATUS_USER_NOT_FOUND)
		return
	}

	res.WriteHeader(http.StatusOK)
}

func (a *Api) userWithPasswordExists(ctx context.Context, userid, password string) bool {
	users, err := a.Store.WithContext(ctx).FindUsers(&User{
		Id: userid,
	})

	return err == nil &&
		len(users) == 1 &&
		!users[0].IsDeleted() &&
		users[0].EmailVerified == true &&
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

func (a *Api) removeCustodianPermissionsForUser(userId string) error {
	if err := a.removeClinicCustodianPermissions(userId); err != nil {
		return err
	}
	if err := a.removeUserPermissions(userId, clients.Permissions{"custodian": clients.Allowed}); err != nil {
		return err
	}
	return nil
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

func (a *Api) removeClinicCustodianPermissions(userId string) error {
	ctx := context.Background()
	id := api.UserId(userId)
	limit := api.Limit(1000)
	params := &api.ListClinicsForPatientParams{
		Limit: &limit,
	}

	perms, err := a.clinic.ListClinicsForPatientWithResponse(ctx, id, params)
	if err != nil {
		return err
	}
	if perms.StatusCode() != http.StatusOK {
		return fmt.Errorf("unexpected status code from clinic service: %v", perms.StatusCode())
	}

	for _, relationship := range *perms.JSON200 {
		if relationship.Patient.Permissions.Custodian != nil {
			clinicId := api.ClinicId(relationship.Clinic.Id)
			patientId := api.PatientId(userId)
			resp, err := a.clinic.DeletePatientPermissionWithResponse(ctx, clinicId, patientId, "custodian")
			if err != nil {
				return err
			}
			if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusNotFound {
				return fmt.Errorf("unexpected status code from clinic service when removing permission: %v", resp.StatusCode())
			}
		}
	}
	return nil
}
