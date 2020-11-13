package user

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/tidepool-org/shoreline/keycloak"
	"golang.org/x/oauth2"
	"github.com/coocood/freecache"
	"time"
)

//go:generate mockgen -source=./tokenAuthenticator.go -destination=./tokenAuthenticator_mock.go -package user TokenAuthenticator
type TokenAuthenticator interface {
	Authenticate(ctx context.Context, token string) (*TokenData, error)
	AuthenticateKeycloakToken(ctx context.Context, token string) (*TokenData, error)
}

type DefaultTokenAuthenticator struct {
	keycloakClient keycloak.Client
	store          Storage
	tokenConfigs   []TokenConfig
}

func NewTokenAuthenticator(client keycloak.Client, storage Storage, configs []TokenConfig) TokenAuthenticator {
	return &DefaultTokenAuthenticator{
		keycloakClient: client,
		store:          storage,
		tokenConfigs:   configs,
	}
}

func (t DefaultTokenAuthenticator) Authenticate(ctx context.Context, token string) (*TokenData, error) {
	if token == "" {
		return nil, errors.New("Session token is empty")
	}

	// if the token is valid jwt and we have the private key it's been signed with it's a legacy token
	if td, err := UnpackSessionTokenAndVerify(token, t.tokenConfigs...); err == nil {
		// verify the token hasn't been revoked
		if _, err = t.store.WithContext(ctx).FindTokenByID(token); err != nil {
			return nil, err
		}
		return td, nil
	}

	return t.AuthenticateKeycloakToken(ctx, token)
}

func (t *DefaultTokenAuthenticator) AuthenticateKeycloakToken(ctx context.Context, token string) (*TokenData, error) {
	var oauthToken *oauth2.Token
	if keycloak.IsKeycloakBackwardCompatibleToken(token) {
		var err error
		if oauthToken, err = keycloak.UnpackBackwardCompatibleToken(token); err != nil {
			return nil, err
		}
	} else {
		oauthToken = &oauth2.Token{
			AccessToken: token,
		}
	}

	result, err := t.keycloakClient.IntrospectToken(ctx, *oauthToken)
	if err != nil {
		return nil, err
	}

	return TokenDataFromIntrospectionResult(result)
}

type authenticatorFn func(ctx context.Context, token string) (*TokenData, error)
type CachingTokenAuthenticator struct {
	cache                 *freecache.Cache
	expirationGracePeriod time.Duration
	delegate              TokenAuthenticator
	shouldCache           func(*TokenData) bool
}

func CacheServerTokensOnly(td *TokenData) bool {
	return td.IsServer
}

func CacheAllTokens(td *TokenData) bool {
	return true
}

type TokenCacheConfig struct {
	Enabled               bool          `envconfig:"TIDEPOOL_TOKEN_CACHE_ENABLED" default:"true"`
	Capacity              int           `envconfig:"TIDEPOOL_TOKEN_CACHE_CAPACITY" default:"10000"`
	GracePeriod           time.Duration `envconfig:"TIDEPOOL_TOKEN_CACHE_EXPIRATION_GRACE_PERIOD" default:"0s"`
	CacheServerTokensOnly bool          `envconfig:"TIDEPOOL_TOKEN_CACHE_SERVER_TOKENS_ONLY" default:"true"`
}

func NewCachingTokenAuthenticator(config *TokenCacheConfig, delegate TokenAuthenticator) TokenAuthenticator {
	shouldCache := CacheAllTokens
	if config.CacheServerTokensOnly {
		shouldCache = CacheServerTokensOnly
	}
	return &CachingTokenAuthenticator{
		cache:                 freecache.NewCache(config.Capacity),
		expirationGracePeriod: config.GracePeriod,
		delegate:              delegate,
		shouldCache:           shouldCache,
	}
}

func (c *CachingTokenAuthenticator) Authenticate(ctx context.Context, token string) (*TokenData, error) {
	return c.authenticateWithCache(ctx, token, c.delegate.Authenticate)
}

func (c *CachingTokenAuthenticator) AuthenticateKeycloakToken(ctx context.Context, token string) (*TokenData, error) {
	return c.authenticateWithCache(ctx, token, c.delegate.AuthenticateKeycloakToken)
}

func (c *CachingTokenAuthenticator) authenticateWithCache(ctx context.Context, token string, delegateFn authenticatorFn) (*TokenData, error) {
	if v, err := c.cache.Get([]byte(token)); err == nil {
		return c.decode(v)
	}

	td, err := delegateFn(ctx, token)
	if err != nil {
		return td, err
	}

	if c.shouldCache(td) {
		if val, err := c.encode(td); err != nil {
			return nil, err
		} else {
			expiration := int(td.ExpiresIn) + int(c.expirationGracePeriod.Seconds())
			if err := c.cache.Set([]byte(token), val, expiration); err != nil {
				return nil, err
			}
		}
	}

	return td, err
}

func (c *CachingTokenAuthenticator) encode(td *TokenData) ([]byte, error) {
	return json.Marshal(td)
}

func (c *CachingTokenAuthenticator) decode(val []byte) (*TokenData, error) {
	td := &TokenData{}
	if err := json.Unmarshal(val, td); err != nil {
		return nil, err
	}
	return td, nil
}
