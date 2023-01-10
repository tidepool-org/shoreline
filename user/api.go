package user

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caos/oidc/pkg/client/rp"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/microcosm-cc/bluemonday"
	log "github.com/sirupsen/logrus"

	"github.com/mdblp/go-common/clients/status"
	"github.com/mdblp/shoreline/auth0"
	"github.com/mdblp/shoreline/schema"
	"github.com/mdblp/shoreline/token"
	"github.com/mdblp/shoreline/user/middlewares"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	exceededConcurrentLoginCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name:      "concurrent_exceeded_login_total",
		Help:      "the total number of concurrent exceeded login",
		Subsystem: "shoreline",
		Namespace: "dblp",
	})
	httpErrorCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "http_errors_total",
		Help:      "The total number of http errors by type of errors",
		Subsystem: "shoreline",
		Namespace: "dblp",
	}, []string{"error_type"})
	inFligthLogin = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "in_flight_login_request",
		Help:      "the total number of concurrent login request",
		Subsystem: "shoreline",
		Namespace: "dblp",
	})
	bmPolicy = bluemonday.StrictPolicy()
	state    = func() string { return uuid.New().String() }
)

type (
	// Api struct used by shoreline server components
	Api struct {
		Store        Storage
		ApiConfig    *ApiConfig
		logger       *log.Logger
		auditLogger  *log.Logger
		loginLimiter LoginLimiter
		provider     rp.RelyingParty
		auth0Client  auth0.ClientInterface
	}
	Secret struct {
		Secret string `json:"secret"`
		Pass   string `json:"pass"`
	}
	OAuthConfig struct {
		DiscoveryUrl string `json:"discoveryUrl"`
		IssuerUri    string `json:"issuer"`
		Secret       string `json:"secret"`
		ClientId     string `json:"clientid"`
		Key          string `json:"key"`
	}
	// ApiConfig for shoreline
	ApiConfig struct {
		//base url which (publicly) exposes shoreline service
		PublicApiURl string
		//base url of front-end, used for oidc login redirect
		FrontUrl string
		//used for services
		ServerSecrets     map[string]string
		LongTermKey       string `json:"longTermKey"`
		LongTermsDuration int64  `json:"longTermDuration"`
		// UserTokenDuration is the token duration for user token
		UserTokenDurationSecs int64
		// ServerTokenDuration is the token duration for server tokens
		ServerTokenDurationSecs int64
		//used for pw
		Salt string `json:"salt"`
		//used for token
		Secret       string `json:"apiSecret"`
		TokenSecrets map[string]string
		//used to delegate auth to OAuth/OIDC server
		OAuthAppConfig OAuthConfig
		// Maximum number of consecutive failed login before a delay is set
		MaxFailedLogin int `json:"maxFailedLogin"`
		// Delay in minutes the user must wait 10min before attempting a new login if the number of
		// consecutive failed login is more than MaxFailedLogin
		DelayBeforeNextLoginAttempt int64 `json:"delayBeforeNextLoginAttempt"`
		// Maximum number of concurrent login
		MaxConcurrentLogin int `json:"maxConcurrentLogin"`
		// Block users to do multiple parallel logins (for load tests we desactivate this)
		BlockParallelLogin bool `json:"blockParallelLogin"`
		//allows for the skipping of verification for testing
		VerificationSecret string `json:"verificationSecret"`
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
	dayAsSecs = int64(1 * 24 * 60 * 60)
	//api logging prefix
	USER_API_PREFIX = "api/user "

	TP_SERVER_NAME    = "x-tidepool-server-name"
	TP_SERVER_SECRET  = "x-tidepool-server-secret"
	TP_SESSION_TOKEN  = "x-tidepool-session-token"
	EXT_SESSION_TOKEN = "x-external-session-token"
	// TP_TRACE_SESSION Session trace: uuid v4
	TP_TRACE_SESSION      = "x-tidepool-trace-session"
	HEADER_REQUEST_SOURCE = "x-backloops-source"

	STATUS_NO_USR_DETAILS                 = "No user details were given"
	STATUS_INVALID_USER_DETAILS           = "Invalid user details were given"
	STATUS_USER_NOT_FOUND                 = "User not found"
	STATUS_ERR_FINDING_USR                = "Error finding user"
	STATUS_ERR_CREATING_USR               = "Error creating the user"
	STATUS_ERR_UPDATING_USR               = "Error updating user"
	STATUS_USR_ALREADY_EXISTS             = "User already exists"
	STATUS_ID_ALREADY_USED                = "OIDC Id is already assigned to another user"
	STATUS_ERR_GENERATING_TOKEN           = "Error generating the token"
	STATUS_ERR_UPDATING_TOKEN             = "Error updating token"
	STATUS_MISSING_USR_DETAILS            = "Not all required details were given"
	STATUS_ERROR_UPDATING_PW              = "Error updating password"
	STATUS_MISSING_ID_PW                  = "Missing id and/or password"
	STATUS_NO_MATCH                       = "No user matched the given details"
	STATUS_NOT_VERIFIED                   = "The user hasn't verified this account yet"
	STATUS_NO_TOKEN_MATCH                 = "No token matched the given details"
	STATUS_PW_WRONG                       = "Wrong password"
	STATUS_ERR_SENDING_EMAIL              = "Error sending email"
	STATUS_NO_TOKEN                       = "No x-tidepool-session-token was found"
	STATUS_SERVER_TOKEN_REQUIRED          = "A server token is required"
	STATUS_AUTH_HEADER_REQUIRED           = "Authorization header is required"
	STATUS_AUTH_HEADER_INVLAID            = "Authorization header is invalid"
	STATUS_GETSTATUS_ERR                  = "Error checking service status"
	STATUS_UNAUTHORIZED                   = "Not authorized for requested operation"
	STATUS_NO_QUERY                       = "A query must be specified"
	STATUS_PARAMETER_UNKNOWN              = "Unknown query parameter"
	STATUS_ONE_QUERY_PARAM                = "Only one query parameter is allowed"
	STATUS_INVALID_ROLE                   = "The role specified is invalid"
	STATUS_INVALID_EMAIL_VERIF_BOOL_PARAM = "The emailVerified query parameter must be a boolean"
	STATUS_OK                             = "OK"
	STATUS_NO_EXPECTED_PWD                = "No expected password is found"
)

// NewConfigFromEnv create the configuration from environnement variables
func NewConfigFromEnv(log *log.Logger) *ApiConfig {
	var err error
	var intValue int
	var found bool
	config := &ApiConfig{
		PublicApiURl:                "http://localhost:9107",
		FrontUrl:                    "http://localhost:3001",
		MaxFailedLogin:              5,
		DelayBeforeNextLoginAttempt: 10, // 10 Minutes
		MaxConcurrentLogin:          100,
		BlockParallelLogin:          true,
		LongTermsDuration:           30 * dayAsSecs,
		UserTokenDurationSecs:       60 * 60,
		ServerTokenDurationSecs:     dayAsSecs,
		Salt:                        "ADihSEI7tOQQP9xfXMO9HfRpXKu1NpIJ",
		ServerSecrets:               make(map[string]string),
		TokenSecrets:                make(map[string]string),
		Secret:                      "abcdefghijklmnopqrstuvwxyz",
		OAuthAppConfig:              OAuthConfig{},
	}
	config.ServerSecrets["default"] = config.Secret
	config.TokenSecrets["default"] = config.Secret

	baseUrl, found := os.LookupEnv("AUTH_BASE_URL")
	if found {
		config.PublicApiURl = baseUrl
	}
	frontUrl, found := os.LookupEnv("FRONT_BASE_URL")
	if found {
		config.FrontUrl = frontUrl
	}
	oidcDiscoveryUrl, found := os.LookupEnv("OIDC_DISCOVERY_URL")
	if found {
		config.OAuthAppConfig.DiscoveryUrl = oidcDiscoveryUrl
	} else {
		log.Fatal("Env var OIDC_DISCOVERY_URL must be provided")
	}
	oidcIssueUrl, found := os.LookupEnv("OIDC_ISSUER_URL")
	if found {
		config.OAuthAppConfig.IssuerUri = oidcIssueUrl
	} else {
		config.OAuthAppConfig.IssuerUri = strings.Split(oidcDiscoveryUrl, "/.")[0]
	}
	oidcClientId, found := os.LookupEnv("OIDC_CLIENT_ID")
	if found {
		config.OAuthAppConfig.ClientId = oidcClientId
	}
	oidcSecret, found := os.LookupEnv("OIDC_CLIENT_SECRET")
	if found {
		config.OAuthAppConfig.Secret = oidcSecret
	}
	cookieKey, found := os.LookupEnv("COOKIE_ENCRYPT_KEY")
	if found {
		config.OAuthAppConfig.Key = cookieKey
	}

	intValue, found, err = getIntFromEnvVar("USER_MAX_FAILED_LOGIN", 1, math.MaxInt16)
	if err != nil {
		log.Fatal(err)
	} else if found {
		config.MaxFailedLogin = intValue
	}

	intValue, found, err = getIntFromEnvVar("USER_DELAY_NEXT_LOGIN", 1, math.MaxInt16)
	if err != nil {
		log.Fatal(err)
	} else if found {
		config.DelayBeforeNextLoginAttempt = int64(intValue)
	}

	intValue, found, err = getIntFromEnvVar("USER_MAX_CONCURRENT_LOGIN", 1, math.MaxInt16)
	if err != nil {
		log.Fatal(err)
	} else if found {
		config.MaxConcurrentLogin = intValue
	}

	blockConcurrentUserLogin, found := os.LookupEnv("USER_BLOCK_CONCURRENT_LOGIN")
	if found && blockConcurrentUserLogin == "false" {
		config.BlockParallelLogin = false
	}

	// server secret may be passed via a separate env variable to accommodate easy secrets injection via Kubernetes
	// The server secret is the password any Tidepool service is supposed to know and pass to shoreline for authentication and for getting token
	// With Mdblp, we consider we can have different server secrets
	// These secrets are hosted in a map[string][string] instead of single string
	// which 1st string represents Server/Service name and 2nd represents the actual secret
	// here we consider this SERVER_SECRET that can be injected via Kubernetes is the one for the default server/service (any Tidepool service)
	serverSecret, found := os.LookupEnv("SERVER_SECRET")
	if found {
		config.ServerSecrets["default"] = serverSecret
	}
	serverSecret, found = os.LookupEnv("AUTHENT_API_SECRET")
	if found {
		config.ServerSecrets["authent_api"] = serverSecret
	}
	serverSecret, found = os.LookupEnv("AUTH0_API_SECRET")
	if found {
		config.ServerSecrets["auth0"] = serverSecret
	}
	// extract the list of token secrets
	zdkSecret, found := os.LookupEnv("ZENDESK_SECRET")
	if found {
		config.TokenSecrets["zendesk"] = zdkSecret
	}

	userSecret, found := os.LookupEnv("API_SECRET")
	if found {
		config.Secret = userSecret
		config.TokenSecrets["default"] = userSecret
	}

	verificationSecret, found := os.LookupEnv("VERIFICATION_SECRET")
	if found {
		config.VerificationSecret = verificationSecret
	}

	longTermKey, found := os.LookupEnv("LONG_TERM_KEY")
	if found {
		config.LongTermKey = longTermKey
	}

	intValue, found, err = getIntFromEnvVar("LONG_TERM_TOKEN_DURATION_DAYS", 1, 60)
	if err != nil {
		log.Fatal(err)
	} else if found {
		config.LongTermsDuration = int64(intValue) * dayAsSecs
	}

	intValue, found, err = getIntFromEnvVar("USER_TOKEN_DURATION_SECS", 60, math.MaxInt32)
	if err != nil {
		log.Fatal(err)
	} else if found {
		config.UserTokenDurationSecs = int64(intValue)
	}
	log.Infof("User token duration: %v", time.Duration(config.UserTokenDurationSecs)*time.Second)

	intValue, found, err = getIntFromEnvVar("SERVER_TOKEN_DURATION_SECS", 60, math.MaxInt32)
	if err != nil {
		log.Fatal(err)
	} else if found {
		config.ServerTokenDurationSecs = int64(intValue)
	}
	log.Infof("Server token duration: %v", time.Duration(config.ServerTokenDurationSecs)*time.Second)

	salt, found := os.LookupEnv("SALT")
	if found && len(salt) > 0 {
		config.Salt = salt
	}

	return config
}

// New create a new shoreline API config
func New(cfg *ApiConfig, logger *log.Logger, store Storage, auditLogger *log.Logger, auth0Client *auth0.Auth0Client) *Api {

	provider := createOidcProvider(logger, cfg, strings.Join([]string{cfg.PublicApiURl, "oauth/callback"}, "/"))
	api := Api{
		Store:       store,
		ApiConfig:   cfg,
		logger:      logger,
		auditLogger: auditLogger,
		provider:    provider,
		auth0Client: auth0Client,
	}

	api.loginLimiter.usersInProgress = list.New()

	return &api
}

// SetHandlers init the HTTP routes handlers
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
	rtr.HandleFunc("/oauth/login", rp.AuthURLHandler(state, a.provider))
	rtr.HandleFunc("/oauth/callback", a.DelegatedLoginCallback)
	rtr.HandleFunc("/oauth/merge", a.UpdateUserWithOauth).Methods("POST")

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
		a.logger.Error(http.StatusInternalServerError, STATUS_GETSTATUS_ERR, err.Error())
		s = status.NewApiStatus(http.StatusInternalServerError, err.Error())
	} else {
		s = status.NewApiStatus(http.StatusOK, "OK")
	}
	if jsonDetails, err := json.Marshal(s); err != nil {
		a.logger.Errorf("Error marshaling StatusApi data [%s]", s)
		http.Error(res, "Error marshaling data for response", http.StatusInternalServerError)
	} else {
		res.Header().Set("content-type", "application/json")
		res.WriteHeader(s.Status.Code)
		res.Write(jsonDetails)
	}
}

// @Summary Get users
// @Description Get users
// @ID shoreline-user-api-getusers
// @Accept  json
// @Produce  json
// @Param role query string false "Role. Exactly one query parameter is required in role, id, emailVerified" Enums(clinic)
// @Param id query string false "List of UserId separated by ,. Exactly one query parameter is required in role, id, emailVerified"
// @Param emailVerified query boolean false "Filter users on emailVerified. Exactly one query parameter is required in role, id, emailVerified"
// @Security TidepoolAuth
// @Success 200 {array} user.User
// @Failure 500 {object} status.Status "message returned:\"Error finding user\" "
// @Failure 400 {object} status.Status "message returned:\"The role specified is invalid\" or \"A query must be specified\" or \"Only one query parameter is allowed\" or \"Unknown query parameter\""
// @Failure 401 {object} status.Status "message returned:\"Not authorized for requested operation\" "
// @Router /users [get]
func (a *Api) GetUsers(res http.ResponseWriter, req *http.Request) {
	log := middlewares.GetLogReq(req)
	log.Info("processing a get users request")

	sessionToken := sanitizeSessionToken(req)
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, err)

	} else if !tokenData.IsServer {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log)

	} else if len(req.URL.Query()) == 0 {
		a.sendError(res, http.StatusBadRequest, STATUS_NO_QUERY, log)

		// we do not authorize more than one query param
	} else if len(req.URL.Query()) > 1 {
		a.sendError(res, http.StatusBadRequest, STATUS_ONE_QUERY_PARAM, log)

	} else if role := sanitizeRequestParam(req, "role"); role != "" && !IsValidRole(role) {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_ROLE, log)

	} else if emailVerified := sanitizeRequestParam(req, "emailVerified"); emailVerified != "" && !IsValidBoolean(emailVerified) {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_EMAIL_VERIF_BOOL_PARAM, log)

	} else {
		userIds := strings.Split(sanitizeRequestParam(req, "id"), ",")
		var users []*User
		switch {
		case emailVerified != "":
			emailVerif, _ := strconv.ParseBool(emailVerified)
			if users, err = a.Store.FindUsersByEmailVerified(req.Context(), emailVerif); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err.Error())
			}
		case role != "":
			if users, err = a.Store.FindUsersByRole(req.Context(), role); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err.Error())
			}
		case len(userIds[0]) > 0:
			if users, err = a.Store.FindUsersWithIds(req.Context(), userIds); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err.Error())
			}
		default:
			a.sendError(res, http.StatusBadRequest, STATUS_PARAMETER_UNKNOWN, log)
		}
		// TODO: Verify no return in case of error here ?
		a.logAudit(req, tokenData, "get users request succedeed")
		log.Info("get users request succedeed")
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
	requestSource := req.Header.Get(HEADER_REQUEST_SOURCE)
	// Random sleep to avoid guessing accounts user.
	time.Sleep(time.Millisecond * time.Duration(rand.Int63n(300)))
	log := middlewares.GetLogReq(req)
	log.Info("processing a creation request")

	if newUserDetails, err := ParseNewUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, log, err)
	} else if err := newUserDetails.Validate(requestSource); err != nil { // TODO: Fix this duplicate work!
		// fallback before returning an error
		status := http.StatusBadRequest
		if err == ErrUserUsernameInvalid {
			if exist := a.Store.ExistDirtyUser(req.Context(), *newUserDetails.Username); exist {
				log.Infof("username dirty: %s", *newUserDetails.Username)
				status = http.StatusConflict
			} else {
				log.Warnf("invalid username not managed: %s", *newUserDetails.Username)
			}
		}
		a.sendError(res, status, STATUS_INVALID_USER_DETAILS, log, err)
	} else if newUser, err := NewUser(newUserDetails, a.ApiConfig.Salt, requestSource); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, log, err)
	} else if existingUser, err := a.Store.FindUsers(req.Context(), newUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, log, err)

	} else if len(existingUser) != 0 {
		a.sendError(res, http.StatusConflict, STATUS_ERR_CREATING_USR, log, fmt.Sprintf("User '%s' already exists", *newUserDetails.Username))

	} else if err := a.Store.UpsertUser(req.Context(), newUser); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_CREATING_USR, log, err)

	} else {
		tokenData := token.TokenData{DurationSecs: extractTokenDuration(req), UserId: newUser.Id, IsServer: false, Role: "unverified"}
		tokenConfig := token.TokenConfig{DurationSecs: a.ApiConfig.UserTokenDurationSecs, Secret: a.ApiConfig.Secret}
		if sessionToken, err := CreateSessionTokenAndSave(req.Context(), &tokenData, tokenConfig, a.Store); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, log, err)
		} else {
			a.logAudit(req, &tokenData, "create user with isClinic{%t}", newUser.IsClinic())
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			a.sendUserWithStatus(res, newUser, http.StatusCreated, false)
			log.Infof("creation request succedeed for username: %s", *newUserDetails.Username)
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
// @Failure 304 {object} status.Status "message returned:\"Error updating user\" or \"Error finding user\" "
// @Failure 500 {object} status.Status "message returned:\"Invalid user details were given\""
// @Failure 409 {object} status.Status "message returned:\"User already exists\" "
// @Failure 401 {object} status.Status "message returned:\"Not authorized for requested operation\" "
// @Failure 400 {object} status.Status "message returned:\"Invalid user details were given\" "
// @Router /user/{userid} [put]
func (a *Api) UpdateUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	log := middlewares.GetLogReq(req)
	log.Info("processing a update user request")
	sessionToken := sanitizeSessionToken(req)
	var auth0User = &schema.UserUpdate{}
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, err)

	} else if updateUserDetails, err := ParseUpdateUserDetails(req.Body); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, log, err)

	} else if err := updateUserDetails.Validate(); err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, log, err)

	} else if updateUserDetails.nFields < 1 {
		a.sendError(res, http.StatusNotModified, STATUS_INVALID_USER_DETAILS, log, "Empty payload")

	} else if originalUser, err := a.Store.FindUser(req.Context(), &User{Id: firstStringNotEmpty(vars["userid"], tokenData.UserId)}); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err)

	} else if originalUser == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, "User not found")

	} else if !a.isAuthorized(tokenData, originalUser.Id) {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, "User does not have permissions")

	} else if updateUserDetails.EmailVerified != nil && !tokenData.IsServer {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, "User does not have permissions")

	} else {

		// TODO: This all needs to be refactored so it can be more thoroughly tested

		if updateUserDetails.Password != nil && !tokenData.IsServer && (originalUser.HasRole("hcp") || originalUser.HasRole("caregiver")) {
			// Caregiver & hcp: Must provide their current password to change it
			// Patient password change is done differently
			// Server token: Can perform the change
			if updateUserDetails.CurrentPassword == nil {
				a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, "Missing current password")
				return
			}
			if !originalUser.PasswordsMatch(*updateUserDetails.CurrentPassword, a.ApiConfig.Salt) {
				a.sendError(res, http.StatusUnauthorized, STATUS_PW_WRONG, log, "User does not have permissions", fmt.Errorf("User '%s' passwords do not match", originalUser.Username))
				return
			}
		}

		// Check role
		if updateUserDetails.Roles != nil {
			if len(updateUserDetails.Roles) != 1 {
				a.sendError(res, http.StatusBadRequest, STATUS_INVALID_USER_DETAILS, log, errors.New("multiple roles were provided"))
				return
			}
			if updateUserDetails.Roles[0] != originalUser.Roles[0] && (originalUser.Roles[0] == "patient" || originalUser.Roles[0] == "hcp") {
				a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, errors.New("patients or HCPs cannot change role"))
				return
			}
			if updateUserDetails.Roles[0] != originalUser.Roles[0] && updateUserDetails.Roles[0] != "hcp" {
				a.sendError(res, http.StatusForbidden, STATUS_UNAUTHORIZED, log, errors.New("caregivers cannot change role for something else than hcp"))
				return
			}
		}

		updatedUser := originalUser.DeepClone()
		if updateUserDetails.Username != nil || updateUserDetails.Emails != nil {
			dupCheck := &User{}
			if updateUserDetails.Username != nil {
				updatedUser.Username = *updateUserDetails.Username
				auth0User.Username = updateUserDetails.Username
				dupCheck.Username = updatedUser.Username
			}
			if updateUserDetails.Emails != nil {
				updatedUser.Emails = updateUserDetails.Emails
				auth0User.Emails = &updateUserDetails.Emails
				dupCheck.Emails = updatedUser.Emails
			}

			if results, err := a.Store.FindUsers(req.Context(), dupCheck); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err)
				return
			} else if len(results) == 1 && results[0].Id != firstStringNotEmpty(vars["userid"], tokenData.UserId) {
				//only throw an error if there is a user with a different id but with the same username/email
				a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS, log)
				return
			} else if len(results) > 1 {
				a.sendError(res, http.StatusConflict, STATUS_USR_ALREADY_EXISTS, log)
				return
			}
		}

		if updateUserDetails.Password != nil {
			if err := updatedUser.HashPassword(*updateUserDetails.Password, a.ApiConfig.Salt); err != nil {
				a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, log, err)
				return
			}
			auth0User.Password = updateUserDetails.Password
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
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, log, err)
		} else {
			if a.auth0Client != nil {
				if usr, err := a.auth0Client.GetUserById(updatedUser.Id); err == nil && usr != nil {
					if usr.Username == updatedUser.Username {
						// no need to update with the same value
						auth0User.Username = nil
					}
					if err := a.auth0Client.UpdateUser(updatedUser.Id, auth0User); err != nil {
						a.logger.Error("Impossible to update user on Auth0: ", err)
					}
				}
			}
			a.logAudit(req, tokenData, "update request succedeed for username:%s, and is a clinician one{%t}", updatedUser.Username, updatedUser.IsClinic())
			log.Infof("update request succedeed for username:%s, and is a clinician one{%t}", updatedUser.Username, updatedUser.IsClinic())
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
	// retrieves logger from context
	log := middlewares.GetLogReq(req)
	log.Info("processing a user info request")
	sessionToken := sanitizeSessionToken(req)
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, err)
	} else {
		var user *User
		if userID := vars["userid"]; userID != "" {
			user = &User{Id: userID, Username: userID, Emails: []string{userID}}
		} else {
			user = &User{Id: tokenData.UserId}
		}

		if results, err := a.Store.FindUsers(req.Context(), user); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err)

		} else if len(results) == 0 {
			// check directly in Aut0
			if a.auth0Client != nil {
				auth0Usr, err := a.auth0Client.GetUser(user.Username)
				if err != nil {
					a.logger.Error("Query to Auth0 failed: ", err)
				} else if auth0Usr != nil {
					foundUser := &User{Id: auth0Usr.UserID, Username: auth0Usr.Username, Roles: auth0Usr.Roles, Emails: auth0Usr.Emails}
					if !a.isAuthorized(tokenData, foundUser.Id) {
						a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log)
						return
					}
					a.sendUser(res, foundUser, tokenData.IsServer)
					return
				}
				if !a.isAuthorized(tokenData, user.Id) {
					a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log)
					return
				}
				auth0Usr, err = a.auth0Client.GetUserById(user.Id)
				if err != nil {
					a.logger.Error("Query to Auth0 failed: ", err)
				} else if auth0Usr != nil {
					foundUser := &User{Id: auth0Usr.UserID, Username: auth0Usr.Username, Roles: auth0Usr.Roles, Emails: auth0Usr.Emails}
					a.sendUser(res, foundUser, tokenData.IsServer)
					return
				}
			}
			a.sendError(res, http.StatusNotFound, STATUS_USER_NOT_FOUND, log)

		} else if len(results) != 1 {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, fmt.Sprintf("Found %d users matching %#v", len(results), user))

		} else if result := results[0]; result == nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, "Found user is nil")

		} else if !a.isAuthorized(tokenData, result.Id) {
			a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log)

		} else {
			a.logAudit(req, tokenData, "get user info request succedeed for username:%s and is a clinician {%t}", result.Username, result.IsClinic())
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
// @Param password body string false "password mandatory for personal request"
// @Security TidepoolAuth
// @Success 202 "User deleted"
// @Failure 500 {string} string ""
// @Failure 403 {object} status.Status "message returned:\"Missing id and/or password\" "
// @Failure 401 {string} string ""
// @Router /user/{userid} [delete]
func (a *Api) DeleteUser(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	log := middlewares.GetLogReq(req)
	td, err := a.authenticateSessionToken(req.Context(), sanitizeSessionToken(req))

	if err != nil {
		log.Error(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Infof("processing a deletion request for userid: %s", td.UserId)

	var id string
	if td.IsServer {
		id = vars["userid"]
		log.Info("processing a deletion request for server")
		log.Debug("operating as server")
	} else {
		id = td.UserId
		log.Infof("processing a deletion request for user id: %s", id)
	}

	pw := getGivenDetail(req)["password"]

	if id != "" && (td.IsServer || pw != "") {

		var err error
		toDelete := &User{Id: id}

		if err = toDelete.HashPassword(pw, a.ApiConfig.Salt); td.IsServer || err == nil {
			if err = a.Store.RemoveUser(req.Context(), toDelete); err == nil {

				a.logAudit(req, td, "deleted request succedeed")
				//cleanup if any
				if !td.IsServer {
					a.Store.RemoveTokenByID(req.Context(), sanitizeSessionToken(req))
				}
				//all good
				res.WriteHeader(http.StatusAccepted)
				return
			}
		}
		log.Error(http.StatusInternalServerError, err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Error(http.StatusForbidden, STATUS_MISSING_ID_PW)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusForbidden, STATUS_MISSING_ID_PW), http.StatusForbidden)
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
	requestSource := req.Header.Get(HEADER_REQUEST_SOURCE)
	log := middlewares.GetLogReq(req)
	user, password, err := unpackAuth(sanitizeRequestHeader(req, "Authorization"))
	if err != nil {
		a.sendError(res, http.StatusBadRequest, STATUS_MISSING_ID_PW, log, err)
		return
	}
	if user == nil {
		a.sendError(res, http.StatusBadRequest, STATUS_MISSING_ID_PW, log)
		return
	}

	log.Infof("processing a login request for username: %s", user.Username)

	// Random sleep to avoid guessing accounts user.
	time.Sleep(time.Millisecond * time.Duration(rand.Int63n(100)))

	code, elem := a.appendUserLoginInProgress(user)
	defer a.removeUserLoginInProgress(elem)
	if code != http.StatusOK {
		exceededConcurrentLoginCounter.Inc()
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, log, fmt.Sprintf("User '%s' has too many ongoing login: %d", user.Username, a.loginLimiter.totalInProgress))

	} else if results, err := a.Store.FindUsers(req.Context(), user); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, STATUS_USER_NOT_FOUND, err)

	} else if len(results) != 1 {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, log, fmt.Sprintf("User '%s' have %d matching results", user.Username, len(results)))

	} else if result := results[0]; result == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, log, fmt.Sprintf("User '%s' is nil", user.Username))

	} else if result.IsDeleted() {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, log, fmt.Sprintf("User '%s' is marked deleted", user.Username))

	} else if !result.CanPerformALogin(a.ApiConfig.MaxFailedLogin) {
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, log, fmt.Sprintf("User '%s' can't perform a login yet", user.Username))

	} else if !result.PasswordsMatch(password, a.ApiConfig.Salt) {
		// Limit login failed
		if err := a.UpdateUserAfterFailedLogin(req.Context(), result); err != nil {
			log.Warnf("User '%s' failed to save failed login status [%s]", user.Username, err.Error())
		}
		log.Warnf("password mismatched")
		a.sendError(res, http.StatusUnauthorized, STATUS_NO_MATCH, log, fmt.Sprintf("User '%s' passwords do not match", user.Username))

	} else if !result.IsEmailVerified(a.ApiConfig.VerificationSecret) {
		a.sendError(res, http.StatusForbidden, STATUS_NOT_VERIFIED, log)

	} else {
		// Login succeed:
		// FIXME, YLP-1065
		if len(result.Roles) == 0 {
			// Default role to patient, if no role is found
			// FIXME Dirty quirk
			result.Roles = []string{"patient"}
			log.Warnf("add default role to patient for username: %s", result.Username)
		}
		if requestSource == "private" && !result.HasRole("patient") {
			log.Infof("Private route login: Adding patient role to user %v", result.Id)
			// Let's add the role patient:
			result.Roles = append([]string{"patient"}, result.Roles...)
			if err := a.Store.UpsertUser(req.Context(), result); err != nil {
				log.Debugf("Login of a non patient user from our private endpoint. Error while adding the role patient: %s", err)
			}
		}

		tokenData := &token.TokenData{DurationSecs: extractTokenDuration(req), UserId: result.Id, Email: result.Username, Name: result.Username, Role: result.Roles[0]}
		tokenConfig := token.TokenConfig{DurationSecs: a.ApiConfig.UserTokenDurationSecs, Secret: a.ApiConfig.Secret}
		if sessionToken, err := CreateSessionTokenAndSave(req.Context(), tokenData, tokenConfig, a.Store); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_TOKEN, log, err)

		} else {
			a.logAudit(req, tokenData, "login succeeded")
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			a.sendUser(res, result, false)
		}

		if err := a.UpdateUserAfterSuccessfulLogin(req.Context(), result); err != nil {
			log.Errorf("Failed to save success login status [%s] for user %#v", err.Error(), result)
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
	server, pw := sanitizeRequestHeader(req, TP_SERVER_NAME), req.Header.Get(TP_SERVER_SECRET)
	log := middlewares.GetLogReq(req)
	log.Infof("processing a server login request for server: %s", server)
	// the expected secret is the secret that the requesting server is supposed to give to be delivered the token
	expectedSecret := ""

	// if server or password is not given we obviously have a problem
	if server == "" || pw == "" {
		log.Error(http.StatusBadRequest, STATUS_MISSING_ID_PW)
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
		log.Error(http.StatusInternalServerError, STATUS_NO_EXPECTED_PWD)
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_NO_EXPECTED_PWD), http.StatusInternalServerError)
		return
	}

	// If the expected secret is the one given at the door then we can generate a token
	if pw == expectedSecret {
		//generate new token
		if sessionToken, err := CreateSessionTokenAndSave(
			req.Context(),
			&token.TokenData{DurationSecs: extractTokenDuration(req), UserId: server, IsServer: true},
			token.TokenConfig{DurationSecs: a.ApiConfig.ServerTokenDurationSecs, Secret: a.ApiConfig.Secret},
			a.Store,
		); err != nil {
			// Error generating the token
			log.Error(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
			return
		} else {
			// Server is provided with the generated token
			a.logAudit(req, nil, "server Login succeeded")
			res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
			return
		}
	}
	// If the password given at the door is wrong, we cannot generate the token
	log.Error(http.StatusUnauthorized, STATUS_PW_WRONG)
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_PW_WRONG), http.StatusUnauthorized)
}

// @Summary Refresh session
// @Description Refresh session
// @ID shoreline-user-api-refreshsession
// @Accept  json
// @Produce  json
// @Param x-tidepool-server-name header string true "server name"
// @Param x-tidepool-server-secret header string true "server secret"
// @Security TidepoolAuth
// @Success 200 {object} token.TokenData  "Token details"
// @Header 200 {string} x-tidepool-session-token "authentication token"
// @Failure 500 {object} status.Status "message returned:\"Error generating the token\" "
// @Failure 401 {string} string ""
// @Router /login [get]
func (a *Api) RefreshSession(res http.ResponseWriter, req *http.Request) {
	td, err := a.authenticateSessionToken(req.Context(), sanitizeSessionToken(req))
	log := middlewares.GetLogReq(req)
	log.Info("processing a refresh session request")

	if err != nil {
		log.Error(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Infof("processing a refresh session request for userid: %s", td.UserId)
	log.Tracef("token data payload : %+v", *td)
	// retrieve User in Db for having last information (role)
	users, errUser := a.Store.FindUsers(req.Context(), &User{Id: td.UserId, Username: td.Email})
	if errUser != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err)
		return
	} else if len(users) == 0 {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, "User not found")
		return
	} else if len(users) > 1 {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, "Duplicate users")
		return
	}
	user := users[0]

	// Set Role
	var role string
	if user.Roles != nil && len(user.Roles) > 0 {
		role = user.Roles[0]
	}
	log.Tracef("user role :%s", role)
	//refresh token with update user information
	newTokenData := token.TokenData{DurationSecs: extractTokenDuration(req), UserId: user.Id, IsServer: false, Role: role}
	tokenConfig := token.TokenConfig{DurationSecs: a.ApiConfig.UserTokenDurationSecs, Secret: a.ApiConfig.Secret}
	if sessionToken, err := CreateSessionTokenAndSave(
		req.Context(),
		&newTokenData,
		tokenConfig,
		a.Store,
	); err != nil {
		log.Error(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else {
		a.logAudit(req, td, "Refresh session token with last user information")
		log.Info("Refresh session token with last user information")
		res.Header().Set(TP_SESSION_TOKEN, sessionToken.ID)
		sendModelAsRes(res, user)
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
	duration := a.ApiConfig.LongTermsDuration
	longtermkey := vars["longtermkey"]
	log := middlewares.GetLogReq(req)
	log.Info("processing a long term loging request")

	if longtermkey == a.ApiConfig.LongTermKey {
		log.Debug("token duration is ", fmt.Sprint(time.Duration(duration)*time.Second))
		req.Header.Add(token.TOKEN_DURATION_KEY, strconv.FormatFloat(float64(duration), 'f', -1, 64))
	} else {
		// tell us there was no match
		log.Warn("tried to login using the longtermkey but it didn't match the stored key")
	}

	// FIXME: Everybody can request a token with an arbitrary duration
	// since, the key check is not done in the login, nor the refresh token
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
// @Success 200 {object} token.TokenData  "Token details"
// @Failure 401 {object} status.Status "message returned:\"No x-tidepool-session-token was found\" "
// @Router /token/{token} [get]
func (a *Api) ServerCheckToken(res http.ResponseWriter, req *http.Request, vars map[string]string) {
	log := middlewares.GetLogReq(req)
	log.Info("processing a server check request")

	if hasServerToken(req.Header.Get(TP_SESSION_TOKEN), a.ApiConfig.Secret) {
		td, err := a.authenticateSessionToken(req.Context(), vars["token"])
		if err != nil {
			log.Errorf("failed request: %v", req)
			log.Error(http.StatusUnauthorized, STATUS_NO_TOKEN, err.Error())
			sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
			return
		}
		sendModelAsRes(res, td)
		return
	}

	log.Info(http.StatusUnauthorized, STATUS_NO_TOKEN)
	log.Debugf("header session token: %v", sanitizeSessionToken(req))
	sendModelAsResWithStatus(res, status.NewStatus(http.StatusUnauthorized, STATUS_NO_TOKEN), http.StatusUnauthorized)
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
	log := middlewares.GetLogReq(req)
	log.Info("processing a logout request")

	if id := sanitizeSessionToken(req); id != "" {
		if err := a.Store.RemoveTokenByID(req.Context(), id); err != nil {
			//silently fail but still log it
			log.Error("Logout was unable to delete token", err.Error())
		}
	}
	// otherwise all good
	a.logAudit(req, nil, "logout request succeeded")
	res.WriteHeader(http.StatusOK)
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
	log := middlewares.GetLogReq(req)
	log.Info("processing a 3rd party token generation request")

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
		log.Error(http.StatusBadRequest, "the service does not exist")
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusBadRequest, STATUS_ERR_GENERATING_TOKEN), http.StatusBadRequest)
		return
	}

	td, err := a.authenticateSessionToken(req.Context(), sanitizeSessionToken(req))

	if err != nil {
		log.Error(http.StatusUnauthorized, err.Error())
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	td.Audience = service
	//refresh
	if sessionToken, err := token.CreateSessionToken(
		td,
		token.TokenConfig{DurationSecs: a.ApiConfig.UserTokenDurationSecs, Secret: secret},
	); err != nil {
		log.Error(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN, err.Error())
		sendModelAsResWithStatus(res, status.NewStatus(http.StatusInternalServerError, STATUS_ERR_GENERATING_TOKEN), http.StatusInternalServerError)
		return
	} else {
		a.logAudit(req, td, "GenerateExternalToken")
		res.Header().Set(EXT_SESSION_TOKEN, sessionToken.ID)
		sendModelAsRes(res, td)
		return
	}
}

func (a *Api) sendError(res http.ResponseWriter, statusCode int, reason string, log *log.Entry, extras ...interface{}) {
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
		httpErrorCounter.WithLabelValues(STATUS_NO_USR_DETAILS).Inc()

	case STATUS_INVALID_USER_DETAILS:
		httpErrorCounter.WithLabelValues(STATUS_INVALID_USER_DETAILS).Inc()

	case STATUS_USER_NOT_FOUND:
		httpErrorCounter.WithLabelValues(STATUS_USER_NOT_FOUND).Inc()

	case STATUS_ERR_FINDING_USR:
		httpErrorCounter.WithLabelValues(STATUS_ERR_FINDING_USR).Inc()

	case STATUS_ERR_CREATING_USR:
		httpErrorCounter.WithLabelValues(STATUS_ERR_CREATING_USR).Inc()

	case STATUS_ERR_UPDATING_USR:
		httpErrorCounter.WithLabelValues(STATUS_ERR_UPDATING_USR).Inc()

	case STATUS_USR_ALREADY_EXISTS:
		httpErrorCounter.WithLabelValues(STATUS_USR_ALREADY_EXISTS).Inc()

	case STATUS_ERR_GENERATING_TOKEN:
		httpErrorCounter.WithLabelValues(STATUS_ERR_GENERATING_TOKEN).Inc()

	case STATUS_ERR_UPDATING_TOKEN:
		httpErrorCounter.WithLabelValues(STATUS_ERR_UPDATING_TOKEN).Inc()

	case STATUS_MISSING_USR_DETAILS:
		httpErrorCounter.WithLabelValues(STATUS_MISSING_USR_DETAILS).Inc()

	case STATUS_ERROR_UPDATING_PW:
		httpErrorCounter.WithLabelValues(STATUS_ERROR_UPDATING_PW).Inc()

	case STATUS_MISSING_ID_PW:
		httpErrorCounter.WithLabelValues(STATUS_MISSING_ID_PW).Inc()

	case STATUS_NO_MATCH:
		httpErrorCounter.WithLabelValues(STATUS_NO_MATCH).Inc()

	case STATUS_NOT_VERIFIED:
		httpErrorCounter.WithLabelValues(STATUS_NOT_VERIFIED).Inc()

	case STATUS_NO_TOKEN_MATCH:
		httpErrorCounter.WithLabelValues(STATUS_NO_TOKEN_MATCH).Inc()

	case STATUS_PW_WRONG:
		httpErrorCounter.WithLabelValues(STATUS_PW_WRONG).Inc()

	case STATUS_ERR_SENDING_EMAIL:
		httpErrorCounter.WithLabelValues(STATUS_ERR_SENDING_EMAIL).Inc()

	case STATUS_NO_TOKEN:
		httpErrorCounter.WithLabelValues(STATUS_NO_TOKEN).Inc()

	case STATUS_SERVER_TOKEN_REQUIRED:
		httpErrorCounter.WithLabelValues(STATUS_SERVER_TOKEN_REQUIRED).Inc()

	case STATUS_AUTH_HEADER_REQUIRED:
		httpErrorCounter.WithLabelValues(STATUS_AUTH_HEADER_REQUIRED).Inc()

	case STATUS_AUTH_HEADER_INVLAID:
		httpErrorCounter.WithLabelValues(STATUS_AUTH_HEADER_INVLAID).Inc()

	case STATUS_GETSTATUS_ERR:
		httpErrorCounter.WithLabelValues(STATUS_GETSTATUS_ERR).Inc()

	case STATUS_UNAUTHORIZED:
		httpErrorCounter.WithLabelValues(STATUS_UNAUTHORIZED).Inc()

	case STATUS_NO_QUERY:
		httpErrorCounter.WithLabelValues(STATUS_NO_QUERY).Inc()

	case STATUS_PARAMETER_UNKNOWN:
		httpErrorCounter.WithLabelValues(STATUS_PARAMETER_UNKNOWN).Inc()

	case STATUS_ONE_QUERY_PARAM:
		httpErrorCounter.WithLabelValues(STATUS_ONE_QUERY_PARAM).Inc()

	case STATUS_INVALID_ROLE:
		httpErrorCounter.WithLabelValues(STATUS_INVALID_ROLE).Inc()
	}

	log.Errorf("%s:%d http response: [%d %s] %s", file, line, statusCode, reason, strings.Join(messages, "; "))
	sendModelAsResWithStatus(res, status.NewStatus(statusCode, reason), statusCode)
}

func (a *Api) authenticateSessionToken(ctx context.Context, sessionToken string) (*token.TokenData, error) {
	if sessionToken == "" {
		return nil, errors.New("session token is empty")
	} else if tokenData, err := token.UnpackSessionTokenAndVerify(sessionToken, a.ApiConfig.Secret); err != nil {
		return nil, err
	} else if _, err := a.Store.FindTokenByID(ctx, sessionToken); err != nil {
		return nil, err
	} else {
		return tokenData, nil
	}
}

func (a *Api) isAuthorized(tokenData *token.TokenData, userID string) bool {
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
