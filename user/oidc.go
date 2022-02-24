package user

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/caos/oidc/pkg/client/rp"
	httphelper "github.com/caos/oidc/pkg/http"
	"github.com/caos/oidc/pkg/oidc"
	"github.com/golang-jwt/jwt"
	"github.com/mdblp/shoreline/token"
	"github.com/mdblp/shoreline/user/middlewares"
	"github.com/sirupsen/logrus"
)

// Simple structure to store and exchange OIDC tokens with our frontend
type OidcTokens struct {
	AuthToken    string `json:"auth"`
	RefreshToken string `json:"refresh"`
}

// Encode tokens to JSON (used to send on HTTP responses)
func (t *OidcTokens) Encode() (string, error) {
	if by, err := json.Marshal(t); err != nil {
		return "", err
	} else {
		return string(by), nil
	}
}

//Decode JSON representation of our OIDC tokens into OidcTokens struct
func (t *OidcTokens) Decode(val string) error {
	if err := json.Unmarshal([]byte(val), t); err != nil {
		return err
	} else {
		return nil
	}
}

// Create a OIDC Relying Party object from shoreline configuration
func createOidcProvider(logger *logrus.Logger, cfg *ApiConfig, redirectUrl string) rp.RelyingParty {

	key := []byte(cfg.OAuthAppConfig.Key)
	cookieHandler := httphelper.NewCookieHandler(key, key)
	if os.Getenv("APP_ENV") == "development" {
		cookieHandler = httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	}

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithCustomDiscoveryUrl(cfg.OAuthAppConfig.DiscoveryUrl),
	}
	provider, err := rp.NewRelyingPartyOIDC(
		cfg.OAuthAppConfig.IssuerUri,
		cfg.OAuthAppConfig.ClientId,
		cfg.OAuthAppConfig.Secret,
		redirectUrl,
		[]string{"openid", "scope_all"},
		options...)

	if err != nil {
		logger.Fatalf("error creating provider %s", err.Error())
	}
	return provider
}

// OIDC callback method
func (a *Api) DelegatedLoginCallback(res http.ResponseWriter, req *http.Request) {
	rp.CodeExchangeHandler(a.processDelegatedLogin, a.provider)(res, req)
}

func (a *Api) redirectToBlipError(res http.ResponseWriter, errorMsg string) {
	a.logger.Print(errorMsg)
	res.Header().Set("location", a.ApiConfig.FrontUrl+"/professional/certify?source=psc&error="+errorMsg)
	res.WriteHeader(http.StatusFound)
}

// Callback method used to process response from OIDC provider
// Will redirect to blip /merge page if the user does not have the oidc subject id already set.
// Will redirect to blip root / if the user is found
// Will redirect to blip /error page if something goes wrong
// Always return HTTP 302
func (a *Api) processDelegatedLogin(res http.ResponseWriter, req *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
	// Extract user info from token
	jwtToken, err := jwt.Parse(tokens.IDToken, nil)
	if jwtToken == nil {
		a.logger.Error("Error while parsing JWT token received from OIDC provider.", err)
		a.redirectToBlipError(res, "Internal server error")
		return
	}
	user := &User{}
	claims := jwtToken.Claims.(jwt.MapClaims)
	user.FrProId = claims["sub"].(string)

	// Prepare oidc cookie
	oidcTokens := OidcTokens{
		AuthToken:    tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}
	if cookieVal, err := oidcTokens.Encode(); err != nil {
		a.logger.Error("Error while encoding JWT token before sending to Blip.", err)
		a.redirectToBlipError(res, "Internal server error")
		return
	} else {
		rp.CookieHandler().SetCookie(res, "ecps-oidc", cookieVal)
	}

	// Try to match the user in our system using the external subject id
	if results, err := a.Store.FindUsers(req.Context(), user); err != nil {
		a.logger.Error("Mongo DB error while looking for a user.", err)
		a.redirectToBlipError(res, "Internal server error")
		return

	} else if len(results) == 0 {
		// User is not already linked to an OIDC account, let's redirect to the merge page
		res.Header().Set("location", a.ApiConfig.FrontUrl+"/professional/certify?source=psc&frproid="+claims["preferred_username"].(string))
	} else if result := results[0]; result == nil {
		a.logger.Errorf("Mongo DB error while looking for a user. User %s is nil", user.FrProId)
		a.redirectToBlipError(res, "Internal server error")

	} else if result.IsDeleted() {
		a.logger.Errorf("User %s is marked deleted", user.FrProId)
		a.redirectToBlipError(res, "User is marked as deleted")

	} else if !result.CanPerformALogin(a.ApiConfig.MaxFailedLogin) {
		a.logger.Infof("User '%s' can't perform a login yet", user.FrProId)
		a.redirectToBlipError(res, "User cannot perform a login yet, re-try later")

	} else if !result.IsEmailVerified(a.ApiConfig.VerificationSecret) {
		a.logger.Infof("User '%s' has not validated their account", user.FrProId)
		a.redirectToBlipError(res, "User cannot perform a login yet, re-try later")

	} else {

		// Login succeed:
		if len(result.Roles) == 0 {
			result.Roles = []string{"hcp"}
		}
		tokenData := &token.TokenData{DurationSecs: extractTokenDuration(req), UserId: result.Id, Email: result.Username, Name: result.Username, Role: result.Roles[0]}
		tokenConfig := token.TokenConfig{DurationSecs: a.ApiConfig.UserTokenDurationSecs, Secret: a.ApiConfig.Secret}
		if sessionToken, err := CreateSessionTokenAndSave(req.Context(), tokenData, tokenConfig, a.Store); err != nil {
			a.logger.Errorf("%s, err: %s", STATUS_ERR_UPDATING_TOKEN, err.Error())
			a.redirectToBlipError(res, "Internal server error")

		} else {
			a.logAudit(req, tokenData, "eCPS Login")
			a.logger.Info(sessionToken)
			res.Header().Set("location", a.ApiConfig.FrontUrl)
		}
	}
	a.logger.Info("blip redirect")
	res.WriteHeader(http.StatusFound)
}

// @Summary Update an HCP user with an external OAuth ID
// @Description Merge an external oauth uid with a yourloops user
// @ID shoreline-user-api-updateOauth
// @Accept  json
// @Produce  json
// @Security TidepoolAuth
// @Security OIDC cookie
// @Success 202 "User updated"
// @Failure 500 {string} string ""
// @Failure 401 {string} string ""
// @Router /oauth/merge [post]
func (a *Api) UpdateUserWithOauth(res http.ResponseWriter, req *http.Request) {
	log := middlewares.GetLogReq(req)
	log.Info("Merge user with an external provider id")
	sessionToken := sanitizeSessionToken(req)
	user := &User{}
	if tokenData, err := a.authenticateSessionToken(req.Context(), sessionToken); err != nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, err)
		return
	} else {
		user.Id = tokenData.UserId
	}

	// Retrieve OAuth token from cookie
	if oAuthCookieVal, err := a.provider.CookieHandler().CheckCookie(req, "ecps-oidc"); err != nil {
		a.sendError(res, http.StatusUnauthorized, "Oauth cookie not provided", log, err)
		return
	} else if oidcId, err := a.retrieveOauthId(oAuthCookieVal); err != nil {
		a.sendError(res, http.StatusInternalServerError, "Error while decoding Oauth cookie", log, err)
	} else {
		user.FrProId = oidcId
	}

	log.Infof("Will merge account %v with idNat %v", user.Id, user.FrProId)

	if originalUser, err := a.Store.FindUser(req.Context(), &User{Id: user.Id}); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err)

	} else if originalUser == nil {
		a.sendError(res, http.StatusUnauthorized, STATUS_UNAUTHORIZED, log, "User not found")

	} else if dupUsers, err := a.Store.FindUsers(req.Context(), &User{FrProId: user.FrProId}); err != nil {
		a.sendError(res, http.StatusInternalServerError, STATUS_ERR_FINDING_USR, log, err)

	} else if len(dupUsers) == 1 && dupUsers[0].Id != user.Id {
		//only throw an error if there is a user with a different id but with the same oidc external id
		a.sendError(res, http.StatusConflict, STATUS_ID_ALREADY_USED, log)

	} else if len(dupUsers) > 1 {
		a.sendError(res, http.StatusConflict, STATUS_ID_ALREADY_USED, log)

	} else {
		// Everything is fine, update the user
		updatedUser := originalUser.DeepClone()
		updatedUser.FrProId = user.FrProId
		if err := a.Store.UpsertUser(req.Context(), updatedUser); err != nil {
			a.sendError(res, http.StatusInternalServerError, STATUS_ERR_UPDATING_USR, log, err)
		} else {
			a.sendUserWithStatus(res, updatedUser, http.StatusAccepted, false)
		}
	}
}

// Extract OAuth/Oidc unique id from our cookie
func (a *Api) retrieveOauthId(cookie string) (string, error) {
	oAuthTokens := OidcTokens{}

	if err := oAuthTokens.Decode(cookie); err != nil {
		return "", err
	} else if jwtToken, _ := jwt.Parse(oAuthTokens.AuthToken, nil); jwtToken == nil {
		return "", err
	} else {
		claims := jwtToken.Claims.(jwt.MapClaims)
		if claims["sub"] == nil {
			return "", errors.New("OIDC token does not contain field 'sub'")
		}
		return claims["sub"].(string), nil
	}
}
