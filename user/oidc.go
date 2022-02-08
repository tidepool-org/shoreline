package user

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/caos/oidc/pkg/client/rp"
	httphelper "github.com/caos/oidc/pkg/http"
	"github.com/caos/oidc/pkg/oidc"
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

// Replace the default behaviour of the oidc discovery edpoint
// Needed because Prosante connect does not use the standard well-known path
func DiscoverEcpsEndpoints(issuer string) (*oidc.DiscoveryConfiguration, error) {
	httpClient := httphelper.DefaultHTTPClient
	// custom well-known path
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/wallet-openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	discoveryConfig := new(oidc.DiscoveryConfiguration)
	err = httphelper.HttpRequest(httpClient, req, &discoveryConfig)
	if err != nil {
		return nil, err
	}
	if discoveryConfig.Issuer != issuer {
		return nil, oidc.ErrIssuerInvalid
	}
	return discoveryConfig, nil
}

// Generate a random key, used to encrypt and sign our http cookie
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Create a OIDC Relying Party object from shoreline configuration
func createOidcProvider(logger *logrus.Logger, cfg *ApiConfig, redirectUrl string) rp.RelyingParty {
	key, err := GenerateRandomBytes(32)

	if err != nil {
		panic("failed to generate oidc secret " + err.Error())
	}

	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	endpoints, _ := DiscoverEcpsEndpoints(cfg.OAuthAppConfig.IssuerUri)
	provider, err := rp.NewRelyingPartyOIDCWithCustomEndpoints(
		cfg.OAuthAppConfig.IssuerUri,
		cfg.OAuthAppConfig.ClientId,
		cfg.OAuthAppConfig.Secret,
		redirectUrl,
		[]string{"openid", "scope_all"},
		endpoints,
		options...)

	if err != nil {
		logger.Fatalf("error creating provider %s", err.Error())
	}
	return provider
}
