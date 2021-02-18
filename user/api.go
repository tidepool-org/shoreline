package user

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/tidepool-org/go-common/clients/status"
	"github.com/tidepool-org/shoreline/user/mailchimp"
	"github.com/tidepool-org/shoreline/user/marketo"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	failedMarketoUploadCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "failedMarketoUploadCounter",
		Help: "The total number of failures to connect to marketo due to errors",
	})
	statusNoUsrDetailsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusNoUsrDetailsCounter",
		Help: "The total number of STATUS_NO_USR_DETAILS errors",
	})
	statusInvalidUserDetailsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusInvalidUserDetailsCounter",
		Help: "The total number of STATUS_INVALID_USER_DETAILS errors",
	})
	statusUserNotFoundCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusUserNotFoundCounter",
		Help: "The total number of STATUS_USER_NOT_FOUND errors",
	})
	statusErrFindingUsrCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusErrFindingUsrCounter",
		Help: "The total number of STATUS_ERR_FINDING_USR errors",
	})
	statusErrCreatingUsrCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusErrCreatingUsrCounter",
		Help: "The total number of STATUS_ERR_CREATING_USR errors",
	})
	statusErrUpdatingUsrCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusErrUpdatingUsrCounter",
		Help: "The total number of STATUS_ERR_UPDATING_USR errors",
	})
	statusUsrAlreadyExistsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusUsrAlreadyExistsCounter",
		Help: "The total number of STATUS_USR_ALREADY_EXISTS errors",
	})
	statusErrGeneratingTokenCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusErrGeneratingTokenCounter",
		Help: "The total number of STATUS_ERR_GENERATING_TOKEN errors",
	})
	statusErrUpdatingTokenCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusErrUpdatingTokenCounter",
		Help: "The total number of STATUS_ERR_UPDATING_TOKEN errors",
	})
	statusMissingUsrDetailsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusMissingUsrDetailsCounter",
		Help: "The total number of STATUS_MISSING_USR_DETAILS errors",
	})
	statusErrorUpdatingPwCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusErrorUpdatingPwCounter",
		Help: "The total number of STATUS_ERROR_UPDATING_PW errors",
	})
	statusMissingIdPwCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusMissingIdPwCounter",
		Help: "The total number of STATUS_MISSING_ID_PW errors",
	})
	statusNoMatchCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusNoMatchCounter",
		Help: "The total number of STATUS_NO_MATCH errors",
	})
	statusNotVerifiedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusNotVerifiedCounter",
		Help: "The total number of STATUS_NOT_VERIFIED errors",
	})
	statusNoTokenMatchCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusNoTokenMatchCounter",
		Help: "The total number of STATUS_NO_TOKEN_MATCH errors",
	})
	statusPwWrongCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusPwWrongCounter",
		Help: "The total number of STATUS_PW_WRONG errors",
	})
	statusErrSendingEmailCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusErrSendingEmailCounter",
		Help: "The total number of STATUS_ERR_SENDING_EMAIL errors",
	})
	statusNoTokenCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusNoTokenCounter",
		Help: "The total number of STATUS_NO_TOKEN errors",
	})
	statusServerTokenRequiredCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusServerTokenRequiredCounter",
		Help: "The total number of STATUS_SERVER_TOKEN_REQUIRED errors",
	})
	statusAuthHeaderRequiredCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusAuthHeaderRequiredCounter",
		Help: "The total number of STATUS_AUTH_HEADER_REQUIRED errors",
	})
	statusAuthHeaderInvlaidCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusAuthHeaderInvlaidCounter",
		Help: "The total number of STATUS_AUTH_HEADER_INVLAID errors",
	})
	statusGetstatusErrCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusGetstatusErrCounter",
		Help: "The total number of STATUS_GETSTATUS_ERR errors",
	})
	statusUnauthorizedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusUnauthorizedCounter",
		Help: "The total number of STATUS_UNAUTHORIZED errors",
	})
	statusNoQueryCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusNoQueryCounter",
		Help: "The total number of STATUS_NO_QUERY errors",
	})
	statusParameterUnknownCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusParameterUnknownCounter",
		Help: "The total number of STATUS_PARAMETER_UNKNOWN errors",
	})
	statusOneQueryParamCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusOneQueryParamCounter",
		Help: "The total number of STATUS_ONE_QUERY_PARAM errors",
	})
	statusInvalidRoleCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "statusInvalidRoleCounter",
		Help: "The total number of STATUS_INVALID_ROLE errors",
	})
)

type (
	Api struct {
		Store            Storage
		ApiConfig        ApiConfig
		logger           *log.Logger
		auditLogger      *log.Logger
		mailchimpManager mailchimp.Manager
		loginLimiter     LoginLimiter
		marketoManager   marketo.Manager
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
		Secret       string `json:"apiSecret"`
		TokenSecrets map[string]string
		// Maximum number of consecutive failed login before a delay is set
		MaxFailedLogin int `json:"maxFailedLogin"`
		// Delay in minutes the user must wait 10min before attempting a new login if the number of
		// consecutive failed login is more than MaxFailedLogin
		DelayBeforeNextLoginAttempt int64 `json:"delayBeforeNextLoginAttempt"`
		// Maximum number of concurrent login
		MaxConcurrentLogin int `json:"maxConcurrentLogin"`
		// Block users to do multiple parallel logins (for load tests we desactivate this)
		BlockParallelLogin bool `json:blockParallelLogin`
		//allows for the skipping of verification for testing
		VerificationSecret string           `json:"verificationSecret"`
		Mailchimp          mailchimp.Config `json:"mailchimp"`
		// to create type/file
		Marketo marketo.Config `json:"marketo"`
	}
	// LoginLimiter var needed to limit the max login attempt on an account
	LoginLimiter struct {
		mutex           sync.Mutex
		usersInProgress *list.List
		totalInProgress int
	}
	varsHandler func(http.ResponseWriter, *http.Request, map[string]string)
)

const (
	//api logging prefix
	USER_API_PREFIX = "api/user "

	TP_SERVER_NAME    = "x-tidepool-server-name"
	TP_SERVER_SECRET  = "x-tidepool-server-secret"
	TP_SESSION_TOKEN  = "x-tidepool-session-token"
	EXT_SESSION_TOKEN = "x-external-session-token"
	// TP_TRACE_SESSION Session trace: uuid v4
	TP_TRACE_SESSION = "x-tidepool-trace-session"

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
	STATUS_PARAMETER_UNKNOWN     = "Unknown query parameter"
	STATUS_ONE_QUERY_PARAM       = "Only one query parameter is allowed"
	STATUS_INVALID_ROLE          = "The role specified is invalid"
	STATUS_OK                    = "OK"
	STATUS_NO_EXPECTED_PWD       = "No expected password is found"
)

func InitApi(cfg ApiConfig, logger *log.Logger, store Storage, auditLogger *log.Logger, manager marketo.Manager) *Api {

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

	api := Api{
		Store:            store,
		ApiConfig:        cfg,
		logger:           logger,
		auditLogger:      auditLogger,
		mailchimpManager: mailchimpManager,
		marketoManager:   manager,
	}

	api.loginLimiter.usersInProgress = list.New()

	return &api
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

	rtr.HandleFunc("/login", a.Login).Methods("POST")
	rtr.HandleFunc("/login", a.RefreshSession).Methods("GET")
	rtr.Handle("/login/{longtermkey}", varsHandler(a.LongtermLogin)).Methods("POST")

	rtr.HandleFunc("/serverlogin", a.ServerLogin).Methods("POST")

	rtr.Handle("/token/{token}", varsHandler(a.ServerCheckToken)).Methods("GET")

	rtr.Handle("/ext-token/{service}", varsHandler(a.Get3rdPartyToken)).Methods("POST")

	rtr.HandleFunc("/logout", a.Logout).Methods("POST")

	rtr.HandleFunc("/private", a.AnonymousIdHashPair).Methods("GET")
}

func (h varsHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	h(res, req, vars)
}

// @Summary Get the api status
// @Description Get the api status
// @ID shoreline-user-api-getstatus
// @Accept  json
// @Produce  json
// @Success 200 "Status ok"
// @Failure 500 {string} string "error description"
// @Router /status [get]
func (a *Api) GetStatus(res http.ResponseWriter, req *http.Request) {
	var s status.ApiStatus
	if err := a.Store.Ping(); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_GETSTATUS_ERR, err.Error())
		s = status.NewApiStatus(http.StatusInternalServerError, err.Error())
	} else {
		s = status.NewApiStatus(http.StatusOK, "OK")
	}
	if jsonDetails, err := json.Marshal(s); err != nil {
		log.Printf("Error marshaling StatusApi data [%s]", s)
		http.Error(res, "Error marshaling data for response", http.StatusInternalServerError)
	} else {
		res.Header().Set("content-type", "application/json")
		res.WriteHeader(s.Status.Code)
		res.Write(jsonDetails)
	}
	return
}

// @Summary Get users
// @Description Get users
// @ID shoreline-user-api-getusers
// @Accept  json
// @Produce  json
// @Param role query string false "Role" Enums(clinic)
// @Param id query string false "List of UserId separated by ,"
// @Security TidepoolAuth
// @Success 200 {array} user.User
// @Failure 500 {object} status.Status "message returned:\"Error finding user\" "
// @Failure 400 {object} status.Status "message returned:\"The role specified is invalid\" or \"A query must be specified\" or \"Only one query parameter is allowed\" or \"Unknown query parameter\""
// @Failure 401 {object} status.Status "message returned:\"Not authorized for requested operation\" "
// @Router /users [get]
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
			if users, err = a.Store.FindUsersByRole(req.Context(), role); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
			}
		case len(userIds[0]) > 0:
			if users, err = a.Store.FindUsersWithIds(req.Context(), userIds); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err.Error())
			}
		default:
			a.sendError(res, http.StatusBadRequest, STATUS_PARAMETER_UNKNOWN)
		}
		// TODO: Verify no return in case of error here ?
		a.logAudit(req, tokenData, "GetUsers")
		a.sendUsers(res, users, tokenData.IsServer)
	}
}

// @Summary Create user
// @Description Create user
// @ID shoreline-user-api-createuser
// @Accept  json
// @Produce  json
// @Param user body user.NewUserDetails true "user details"
// @Success 201 {object} user.User
// @Header 201 {string} x-tidepool-session-token "authentication token"
// @Failure 500 {object} status.Status "message returned:\"Error creating the user\" or \"Error generating the token\" "
// @Failure 400 {object} status.Status "message returned:\"Invalid user details were given\" "
// @Router /user [post]
func (a *Api) CreateUser(res http.ResponseWriter, req *http.Request) {
	// Random sleep to avoid guessing accounts user.
	time.Sleep(time.Millisecond * time.Duration(rand.Int63n(300)))

	if newUserDetails, err := ParseNewUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)
	} else if err := newUserDetails.Validate(); err != nil { // TODO: Fix this duplicate work!
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)
	} else if newUser, err := NewUser(newUserDetails, a.ApiConfig.Salt); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)
	} else if existingUser, err := a.Store.FindUsers(req.Context(), newUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else if len(existingUser) != 0 {
		a.sendError(res, http.StatusConflict, STATUS_ERR_CREATING_USR, fmt.Sprintf("User '%s' already exists", *newUserDetails.Username))

	} else if err := a.Store.UpsertUser(req.Context(), newUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, err)

	} else {
		tokenData := TokenData{DurationSecs: extractTokenDuration(req), UserId: newUser.Id, IsServer: false, Role: "unverified"}
		tokenConfig := TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret}
		if sessionToken, err := CreateSessionTokenAndSave(req.Context(), &tokenData, tokenConfig, a.Store); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err)
		} else {
			a.logAudit(req, &tokenData, "CreateUser isClinic{%t}", newUser.IsClinic())
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			a.sendUserWithStatus(res, newUser, http.StatusCreated, false)
		}
	}
}

// @Summary Update user
// @Description Update user
// @ID shoreline-user-api-updateuser
// @Accept  json
// @Produce  json
// @Param userid path int true "user id"
// @Param user body user.UpdateUserDetails true "user update details"
// @Security TidepoolAuth
// @Success 200 {object} user.UpdateUserDetails
// @Failure 500 {object} status.Status "message returned:\"Error updating user\" or \"Error finding user\" "
// @Failure 409 {object} status.Status "message returned:\"User already exists\" "
// @Failure 401 {object} status.Status "message returned:\"Not authorized for requested operation\" "
// @Failure 400 {object} status.Status "message returned:\"Invalid user details were given\" "
// @Router /user/{userid} [put]
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	a.logger.Printf("UpdateUser %v", req)
	sessionToken := req.Header.Get(TP_SESSION_TOKEN)
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, err)

	} else if updateUserDetails, err := ParseUpdateUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if err := updateUserDetails.Validate(); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, err)

	} else if originalUser, err := a.Store.FindUser(req.Context(), &User{Id: firstStringNotEmpty(vars["userid"], tokenData.UserId)}); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

	} else if originalUser == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "User not found")

	} else if !a.isAuthorized(tokenData, originalUser.Id) {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, "User does not have permissions")

	} else if (updateUserDetails.Roles != nil || updateUserDetails.EmailVerified != nil) && !tokenData.IsServer {
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

			if results, err := a.Store.FindUsers(req.Context(), dupCheck); err != nil {
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

		if err := a.Store.UpsertUser(req.Context(), updatedUser); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, err)
		} else {
			if updatedUser.EmailVerified && updatedUser.TermsAccepted != "" {
				if a.mailchimpManager != nil {
					if updateUserDetails.EmailVerified != nil || updateUserDetails.TermsAccepted != nil {
						a.mailchimpManager.CreateListMembershipForUser(updatedUser)
					} else {
						a.mailchimpManager.UpdateListMembershipForUser(originalUser, updatedUser)
					}
				}
				if a.marketoManager != nil && a.marketoManager.IsAvailable() {
					if updateUserDetails.EmailVerified != nil || updateUserDetails.TermsAccepted != nil {
						a.marketoManager.CreateListMembershipForUser(updatedUser)
					} else {
						a.marketoManager.UpdateListMembershipForUser(originalUser, updatedUser)
					}
				} else if a.marketoManager != nil {
					failedMarketoUploadCounter.Inc()
				}
			}
			a.logAudit(req, tokenData, "UpdateUser isClinic{%t}", updatedUser.IsClinic())
			a.sendUser(res, updatedUser, tokenData.IsServer)
		}
	}
}

// @Summary Get user information
// @Description Get user information
// @ID shoreline-user-api-getuserinfo
// @Accept  json
// @Produce  json
// @Param userid path int true "user id" optional
// @Security TidepoolAuth
// @Success 200 {object} user.User
// @Failure 500 {object} status.Status "message returned:\"Error finding user\" "
// @Failure 404 {object} status.Status "message returned:\"User not found\" "
// @Failure 401 {object} status.Status "message returned:\"Not authorized for requested operation\" "
// @Router /user/{userid} [get]
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

		if results, err := a.Store.FindUsers(req.Context(), user); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, err)

		} else if len(results) == 0 {
			a.sendError(res, http.StatusNotFound, STATUS_USER_NOT_FOUND)

		} else if len(results) != 1 {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, fmt.Sprintf("Found %d users matching %#v", len(results), user))

		} else if result := results[0]; result == nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, "Found user is nil")

		} else if !a.isAuthorized(tokenData, result.Id) {
			a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED)

		} else {
			a.logAudit(req, tokenData, "GetUserInfo isClinic{%t}", result.IsClinic())
			a.sendUser(res, result, tokenData.IsServer)
		}
	}
}

// @Summary Delete user
// @Description Delete user
// @ID shoreline-user-api-deleteuser
// @Accept  json
// @Produce  json
// @Param userid path int true "user id for server request, from token for personal request" optional
// @Param password body string true "password"
// @Security TidepoolAuth
// @Success 202 "User deleted"
// @Failure 500 {string} string ""
// @Failure 403 {object} status.Status "message returned:\"Missing id and/or password\" "
// @Failure 401 {string} string ""
// @Router /user/{userid} [delete]
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
			if err = a.Store.RemoveUser(req.Context(), toDelete); err == nil {

				a.logAudit(req, td, "DeleteUser")
				//cleanup if any
				if td.IsServer == false {
					a.Store.RemoveTokenByID(req.Context(), req.Header.Get(TP_SESSION_TOKEN))
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

// @Summary Login user
// @Description Login user
// @ID shoreline-user-api-login
// @Accept  json
// @Produce  json
// @Param tokenduration header number false "token duration"
// @Security BasicAuth
// @Success 200 {object} user.User
// @Header 200 {string} x-tidepool-session-token "au"
// @Failure 500 {object} status.Status "message returned: \"Error updating token\""
// @Failure 403 {object} status.Status "message returned: \"The user hasn't verified this account yet\""
// @Failure 401 {object} status.Status "message returned: \"No user matched the given details\""
// @Failure 400 {object} status.Status "message returned: \"Missing id and/or password\""
// @Router /login [post]
func (a *Api) Login(res http.ResponseWriter, req *http.Request) {
	user, password := unpackAuth(req.Header.Get("Authorization"))
	if user == nil {
		a.sendError(res, http.StatusBadRequest, STATUS_MISSING_ID_PW)
		return
	}

	// Random sleep to avoid guessing accounts user.
	time.Sleep(time.Millisecond * time.Duration(rand.Int63n(100)))

	code, elem := a.appendUserLoginInProgress(user)
	defer a.removeUserLoginInProgress(elem)
	if code != http.StatusOK {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, fmt.Sprintf("User '%s' has too many ongoing login: %d", user.Username, a.loginLimiter.totalInProgress))

	} else if results, err := a.Store.FindUsers(req.Context(), user); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, STATUS_USER_NOT_FOUND, err)

	} else if len(results) != 1 {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, fmt.Sprintf("User '%s' have %d matching results", user.Username, len(results)))

	} else if result := results[0]; result == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, fmt.Sprintf("User '%s' is nil", user.Username))

	} else if result.IsDeleted() {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, fmt.Sprintf("User '%s' is marked deleted", user.Username))

	} else if !result.CanPerformALogin(a.ApiConfig.MaxFailedLogin) {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, fmt.Sprintf("User '%s' can't perform a login yet", user.Username))

	} else if !result.PasswordsMatch(password, a.ApiConfig.Salt) {
		// Limit login failed
		if err := a.UpdateUserAfterFailedLogin(req.Context(), result); err != nil {
			a.logger.Printf("User '%s' failed to save failed login status [%s]", user.Username, err.Error())
		}
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, fmt.Sprintf("User '%s' passwords do not match", user.Username))

	} else if !result.IsEmailVerified(a.ApiConfig.VerificationSecret) {
		a.sendError(res, http.StatusForbidden, STATUS_NOT_VERIFIED)

	} else {
		// TODO: replace this workaround, there should be only one role when the data is cleaned up
		role := "patient"
		if result.Roles != nil && len(result.Roles) > 0 {
			role = result.Roles[0]
		}
		tokenData := &TokenData{DurationSecs: extractTokenDuration(req), UserId: result.Id, Email: result.Username, Name: result.Username, Role: role}
		tokenConfig := TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret}
		if sessionToken, err := CreateSessionTokenAndSave(req.Context(), tokenData, tokenConfig, a.Store); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN, err)

		} else {
			a.logAudit(req, tokenData, "Login")
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			a.sendUser(res, result, false)
		}

		if err := a.UpdateUserAfterSuccessfulLogin(req.Context(), result); err != nil {
			a.logger.Printf("Failed to save success login status [%s] for user %#v", err.Error(), result)
		}
	}
}

// @Summary Login server
// @Description Login server
// @ID shoreline-user-api-serverlogin
// @Accept  json
// @Produce  json
// @Param x-tidepool-server-name header string true "server name"
// @Param x-tidepool-server-secret header string true "server secret"
// @Success 200  "Authentication successfull"
// @Header 200 {string} x-tidepool-session-token "authentication token"
// @Failure 500 {object} status.Status "message returned:\"Error generating the token\" or \"No expected password is found\""
// @Failure 401 {object} status.Status "message returned:\"Wrong password\" "
// @Failure 400 {object} status.Status "message returned:\"Missing id and/or password\" "
// @Router /serverlogin [post]
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
			req.Context(),
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
			a.logAudit(req, nil, "ServerLogin")
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			return
		}
	}
	// If the password given at the door is wrong, we cannot generate the token
	a.logger.Println(http.StatusUnauthorized, STATUS_PW_WRONG)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
	return
}

// @Summary Refresh session
// @Description Refresh session
// @ID shoreline-user-api-refreshsession
// @Accept  json
// @Produce  json
// @Param x-tidepool-server-name header string true "server name"
// @Param x-tidepool-server-secret header string true "server secret"
// @Security TidepoolAuth
// @Success 200 {object} user.TokenData  "Token details"
// @Header 200 {string} x-tidepool-session-token "authentication token"
// @Failure 500 {object} status.Status "message returned:\"Error generating the token\" "
// @Failure 401 {string} string ""
// @Router /login [get]
func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {

	td, err := a.authenticateSessionToken(req.Context(), req.Header.Get(TP_SESSION_TOKEN))

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	//refresh
	if sessionToken, err := CreateSessionTokenAndSave(
		req.Context(),
		td,
		TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: a.ApiConfig.Secret},
		a.Store,
	); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else {
		a.logAudit(req, td, "RefreshSession")
		res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
		sendModelAsRes(res, td)
		return
	}
}

// @Summary Longterm login
// @Description Longterm login
// @ID shoreline-user-api-longtermlogin
// @Accept  json
// @Produce  json
// @Param longtermkey path string true "long term key"
// @Security BasicAuth
// @Success 200 {object} user.User
// @Header 200 {string} x-tidepool-session-token "authentication token"
// @Failure 500 {object} status.Status "message returned:\"Error finding user\" or \"Error updating token\" "
// @Failure 403 {object} status.Status "message returned:\"The user hasn't verified this account yet\" "
// @Failure 401 {object} status.Status "message returned:\"No user matched the given details\" "
// @Failure 400 {object} status.Status "message returned:\"Missing id and/or password\" "
// @Router /login/{longtermkey} [post]
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

// @Summary Check server token
// @Description Check server token
// @ID shoreline-user-api-serverchecktoken
// @Accept  json
// @Produce  json
// @Param token path string true "server token to check"
// @Security TidepoolAuth
// @Success 200 {object} user.TokenData  "Token details"
// @Failure 401 {object} status.Status "message returned:\"No x-tidepool-session-token was found\" "
// @Router /token/{token} [get]
func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	if hasServerToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret) {
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

// @Summary Logout
// @Description Logout
// @ID shoreline-user-api-logout
// @Accept  json
// @Produce  json
// @Security TidepoolAuth
// @Success 200 {string} string ""
// @Router /logout [post]
func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	if id := req.Header.Get(TP_SESSION_TOKEN); id != "" {
		if err := a.Store.RemoveTokenByID(req.Context(), id); err != nil {
			//silently fail but still log it
			a.logger.Println("Logout was unable to delete token", err.Error())
		}
	}
	// otherwise all good
	a.logAudit(req, nil, "Logout")
	res.WriteHeader(http.StatusOK)
	return
}

// @Summary AnonymousIdHashPair ?
// @Description AnonymousIdHashPair ?
// @ID shoreline-user-api-anonymousidhashpair
// @Accept  json
// @Produce  json
// @Success 200 {object} user.AnonIdHashPair "AnonymousIdHashPair?"
// @Router /private [get]
func (a *Api) AnonymousIdHashPair(res http.ResponseWriter, req *http.Request) {
	idHashPair := NewAnonIdHashPair([]string{a.ApiConfig.Salt}, req.URL.Query())
	sendModelAsRes(res, idHashPair)
	return
}

// @Summary Generate a 3rd party JWT
// @Description Generate a token to authenticate the user to a 3rd party service
// @ID shoreline-user-api-getToken
// @Param service path string true "3rd party service name"
// @Security TidepoolAuth
// @Success 200 {object} status.Status
// @Header 200 {string} x-external-session-token "3rd party token"
// @Failure 500 {object} status.Status "message returned:\"Error generating the token" "
// @Failure 401 {object} status.Status "message returned:\"Not authorized for requested operation\" "
// @Failure 400 {object} status.Status "message returned:\"Unknown query parameter\" or \"Error generating the token\" "
// @Router /ext-token/{service} [post]
func (a *Api) Get3rdPartyToken(res http.ResponseWriter, req *http.Request, vars map[string]string) {

	secret := ""
	service := vars["service"]
	if service == "" {
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_PARAMETER_UNKNOWN), http.StatusBadRequest)
		return
	} else {
		secret = a.ApiConfig.TokenSecrets[service]
	}

	if secret == "" {
		// the secret is not defined for this service
		a.logger.Println(http.StatusBadRequest, "the service does not exist")
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_ERR_GENERATING_TOKEN), http.StatusBadRequest)
		return
	}

	td, err := a.authenticateSessionToken(req.Context(), req.Header.Get(TP_SESSION_TOKEN))

	if err != nil {
		a.logger.Println(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	td.Audience = service
	//refresh
	if sessionToken, err := CreateSessionToken(
		td,
		TokenConfig{DurationSecs: a.ApiConfig.TokenDurationSecs, Secret: secret},
	); err != nil {
		a.logger.Println(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else {
		a.logAudit(req, td, "GenerateExternalToken")
		res.Header().Set(EXT_SESSION_TOKEN, sessionToken.ID)
		sendModelAsRes(res, td)
		return
	}
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

	switch reason {
	case STATUS_NO_USR_DETAILS:
		statusNoUsrDetailsCounter.Inc()

	case STATUS_INVALID_USER_DETAILS:
		statusInvalidUserDetailsCounter.Inc()

	case STATUS_USER_NOT_FOUND:
		statusUserNotFoundCounter.Inc()

	case STATUS_ERR_FINDING_USR:
		statusErrFindingUsrCounter.Inc()

	case STATUS_ERR_CREATING_USR:
		statusErrCreatingUsrCounter.Inc()

	case STATUS_ERR_UPDATING_USR:
		statusErrUpdatingUsrCounter.Inc()

	case STATUS_USR_ALREADY_EXISTS:
		statusUsrAlreadyExistsCounter.Inc()

	case STATUS_ERR_GENERATING_TOKEN:
		statusErrGeneratingTokenCounter.Inc()

	case STATUS_ERR_UPDATING_TOKEN:
		statusErrUpdatingTokenCounter.Inc()

	case STATUS_MISSING_USR_DETAILS:
		statusMissingUsrDetailsCounter.Inc()

	case STATUS_ERROR_UPDATING_PW:
		statusErrorUpdatingPwCounter.Inc()

	case STATUS_MISSING_ID_PW:
		statusMissingIdPwCounter.Inc()

	case STATUS_NO_MATCH:
		statusNoMatchCounter.Inc()

	case STATUS_NOT_VERIFIED:
		statusNotVerifiedCounter.Inc()

	case STATUS_NO_TOKEN_MATCH:
		statusNoTokenMatchCounter.Inc()

	case STATUS_PW_WRONG:
		statusPwWrongCounter.Inc()

	case STATUS_ERR_SENDING_EMAIL:
		statusErrSendingEmailCounter.Inc()

	case STATUS_NO_TOKEN:
		statusNoTokenCounter.Inc()

	case STATUS_SERVER_TOKEN_REQUIRED:
		statusServerTokenRequiredCounter.Inc()

	case STATUS_AUTH_HEADER_REQUIRED:
		statusAuthHeaderRequiredCounter.Inc()

	case STATUS_AUTH_HEADER_INVLAID:
		statusAuthHeaderInvlaidCounter.Inc()

	case STATUS_GETSTATUS_ERR:
		statusGetstatusErrCounter.Inc()

	case STATUS_UNAUTHORIZED:
		statusUnauthorizedCounter.Inc()

	case STATUS_NO_QUERY:
		statusNoQueryCounter.Inc()

	case STATUS_PARAMETER_UNKNOWN:
		statusParameterUnknownCounter.Inc()

	case STATUS_ONE_QUERY_PARAM:
		statusOneQueryParamCounter.Inc()

	case STATUS_INVALID_ROLE:
		statusInvalidRoleCounter.Inc()
	}

	a.logger.Printf("%s:%d RESPONSE ERROR: [%d %s] %s", file, line, statusCode, reason, strings.Join(messages, "; "))
	sendModelAsResWithStatus(res, status.NewStatus(statusCode, reason), statusCode)
}

func (a *Api) authenticateSessionToken(ctx context.Context, sessionToken string) (*TokenData, error) {
	if sessionToken == "" {
		return nil, errors.New("Session token is empty")
	} else if tokenData, err := UnpackSessionTokenAndVerify(sessionToken, a.ApiConfig.Secret); err != nil {
		return nil, err
	} else if _, err := a.Store.FindTokenByID(ctx, sessionToken); err != nil {
		return nil, err
	} else {
		return tokenData, nil
	}
}

func (a *Api) isAuthorized(tokenData *TokenData, userID string) bool {
	if tokenData.IsServer {
		return true
	}
	if tokenData.UserId == userID {
		return true
	}
	return false
}

// UpdateUserAfterFailedLogin update the user failed login infos in database
func (a *Api) UpdateUserAfterFailedLogin(ctx context.Context, u *User) error {
	if u.FailedLogin == nil {
		u.FailedLogin = new(FailedLoginInfos)
	}
	u.FailedLogin.Count++
	u.FailedLogin.Total++
	if u.FailedLogin.Count >= a.ApiConfig.MaxFailedLogin {
		nextAttemptTime := time.Now().Add(time.Minute * time.Duration(a.ApiConfig.DelayBeforeNextLoginAttempt))
		u.FailedLogin.NextLoginAttemptTime = nextAttemptTime.Format(time.RFC3339)
	}
	return a.Store.UpsertUser(ctx, u)
}

// UpdateUserAfterSuccessfulLogin update the user after a successful login
func (a *Api) UpdateUserAfterSuccessfulLogin(ctx context.Context, u *User) error {
	if u.FailedLogin != nil && u.FailedLogin.Count > 0 {
		u.FailedLogin.Count = 0
		return a.Store.UpsertUser(ctx, u)
	}
	return nil
}
