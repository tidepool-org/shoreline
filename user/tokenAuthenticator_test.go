package user

import (
	"github.com/golang/mock/gomock"
	"github.com/tidepool-org/shoreline/keycloak"
	"golang.org/x/oauth2"
	"testing"
	"time"
)

var cacheConfig = &TokenCacheConfig{
	Enabled:               true,
	Capacity:              10,
	GracePeriod:           0,
	CacheServerTokensOnly: true,
}

func assertTokensAreEqual(t *testing.T, expected *TokenData, result *TokenData) {
	if expected == nil && result == nil {
		return
	} else if expected == nil && result != nil {
		t.Fatalf("expected result token to be nil")
	} else if expected != nil && result == nil {
		t.Fatalf("expected result token to not be nil")
	} else if expected != nil && result != nil {
		if expected.UserId != result.UserId {
			t.Fatalf("User id doesn't match. Expected %v, got: %v", expected.UserId, result.UserId)
		}
		if expected.IsServer != result.IsServer {
			t.Fatalf("IsServer don't match. Expected %v, got: %v", expected.IsServer, result.IsServer)
		}
		if expected.ExpiresAt != result.ExpiresAt {
			t.Fatalf("ExpiresAt don't match. Expected %v, got: %v", expected.ExpiresAt, result.ExpiresAt)
		}
	}
}

func Test_CachingTokenAuthenticator_AuthenticateKeycloakToken_CachesServerTokens(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mock := NewMockTokenAuthenticator(mockCtrl)
	cachingTokenAuthenticator := NewCachingTokenAuthenticator(cacheConfig, mock)

	token := "asdf"
	expiresAt := time.Now().Unix() + 645
	expectedTokenData := &TokenData{
		IsServer:  true,
		UserId:    "1234567890",
		ExpiresAt: expiresAt,
	}

	// Expect to be called one time with the given arguments
	mock.EXPECT().
		AuthenticateKeycloakToken(gomock.Any(), token).
		Return(expectedTokenData, nil)

	res, err := cachingTokenAuthenticator.AuthenticateKeycloakToken(nil, token)
	if err != nil {
		t.Fatalf("error occurred: %v", err)
	}
	assertTokensAreEqual(t, expectedTokenData, res)

	// The mock expectation will fail if the token was not retrieved from cache
	// and the delegate was called twice
	res, err = cachingTokenAuthenticator.AuthenticateKeycloakToken(nil, token)
	if err != nil {
		t.Errorf("error occurred: %v", err)
	}
	assertTokensAreEqual(t, expectedTokenData, res)
}

func Test_CachingTokenAuthenticator_AuthenticateKeycloakToken_DoesntCacheUserTokens(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mock := NewMockTokenAuthenticator(mockCtrl)
	cachingTokenAuthenticator := NewCachingTokenAuthenticator(cacheConfig, mock)

	token := "asdf"
	expiresAt := time.Now().Unix() + 645
	expectedTokenData := &TokenData{
		IsServer:  false,
		UserId:    "1234567890",
		ExpiresAt: expiresAt,
	}

	// Expect to be called two times with the given arguments
	mock.EXPECT().
		AuthenticateKeycloakToken(gomock.Any(), token).
		Return(expectedTokenData, nil).
		Times(2)

	res, err := cachingTokenAuthenticator.AuthenticateKeycloakToken(nil, token)
	if err != nil {
		t.Fatalf("error occurred: %v", err)
	}
	assertTokensAreEqual(t, expectedTokenData, res)

	// The mock expectation will fail if the token was not retrieved from cache
	// and the delegate was called twice
	res, err = cachingTokenAuthenticator.AuthenticateKeycloakToken(nil, token)
	if err != nil {
		t.Errorf("error occurred: %v", err)
	}
	assertTokensAreEqual(t, expectedTokenData, res)
}

func Test_CachingTokenAuthenticator_Authenticate_CachesServerTokens(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mock := NewMockTokenAuthenticator(mockCtrl)
	cachingTokenAuthenticator := NewCachingTokenAuthenticator(cacheConfig, mock)

	token := "asdf"
	expiresAt := time.Now().Unix() + 645
	expectedTokenData := &TokenData{
		IsServer:  true,
		UserId:    "1234567890",
		ExpiresAt: expiresAt,
	}

	// Expect to be called one time with the given arguments
	mock.EXPECT().
		Authenticate(gomock.Any(), token).
		Return(expectedTokenData, nil)

	res, err := cachingTokenAuthenticator.Authenticate(nil, token)
	if err != nil {
		t.Fatalf("error occurred: %v", err)
	}
	assertTokensAreEqual(t, expectedTokenData, res)

	// The mock expectation will fail if the token was not retrieved from cache
	// and the delegate was called twice
	res, err = cachingTokenAuthenticator.AuthenticateKeycloakToken(nil, token)
	if err != nil {
		t.Errorf("error occurred: %v", err)
	}
	assertTokensAreEqual(t, expectedTokenData, res)
}

func Test_CachingTokenAuthenticator_Authenticate_DoesntCacheUserTokens(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mock := NewMockTokenAuthenticator(mockCtrl)
	cachingTokenAuthenticator := NewCachingTokenAuthenticator(cacheConfig, mock)

	token := "asdf"
	expiresAt := time.Now().Unix() + 645
	expectedTokenData := &TokenData{
		IsServer:  false,
		UserId:    "1234567890",
		ExpiresAt: expiresAt,
	}

	// Expect to be called two times with the given arguments
	mock.EXPECT().
		Authenticate(gomock.Any(), token).
		Return(expectedTokenData, nil).
		Times(2)

	res, err := cachingTokenAuthenticator.Authenticate(nil, token)
	if err != nil {
		t.Fatalf("error occurred: %v", err)
	}
	assertTokensAreEqual(t, expectedTokenData, res)

	// The mock expectation will fail if the token was not retrieved from cache
	// and the delegate was called twice
	res, err = cachingTokenAuthenticator.Authenticate(nil, token)
	if err != nil {
		t.Errorf("error occurred: %v", err)
	}
	assertTokensAreEqual(t, expectedTokenData, res)
}

func Test_TokenAuthenticator_AuthenticateKeycloak_IntrospectsBackwardCompatibleTokens(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := keycloak.NewMockClient(mockCtrl)
	tokenAuthenticator := NewTokenAuthenticator(mockKeycloakClient, nil, nil)

	token := "kc:access_token:refresh_token"
	subject := "1234567890"
	expiresAt := time.Now().Unix() + 645
	introspection := &keycloak.TokenIntrospectionResult{
		Active:        true,
		Subject:       subject,
		EmailVerified: true,
		ExpiresAt:     expiresAt,
		RealmAccess:   keycloak.RealmAccess{},
	}
	expectedTokenData := &TokenData{
		IsServer:     false,
		UserId:       subject,
		ExpiresAt:    expiresAt,
	}

	// Expect to be called called once
	mockKeycloakClient.EXPECT().
		IntrospectToken(gomock.Any(), oauth2.Token{
			AccessToken:  "access_token",
			RefreshToken: "refresh_token",
		}).
		Return(introspection, nil)

	res, err := tokenAuthenticator.AuthenticateKeycloakToken(nil, token)
	if err != nil {
		t.Fatalf("error occurred: %v", err)
	}

	assertTokensAreEqual(t, expectedTokenData, res)
}

func Test_TokenAuthenticator_AuthenticateKeycloak_IntrospectsAccessTokens(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := keycloak.NewMockClient(mockCtrl)
	tokenAuthenticator := NewTokenAuthenticator(mockKeycloakClient, nil, nil)

	token := "access_token"
	subject := "1234567890"
	expiresAt := time.Now().Unix() + 645
	introspection := &keycloak.TokenIntrospectionResult{
		Active:        true,
		Subject:       subject,
		EmailVerified: true,
		ExpiresAt:     expiresAt,
		RealmAccess:   keycloak.RealmAccess{},
	}
	expectedTokenData := &TokenData{
		IsServer:     false,
		UserId:       subject,
		ExpiresAt:    expiresAt,
	}

	// Expect to be called called once
	mockKeycloakClient.EXPECT().
		IntrospectToken(gomock.Any(), oauth2.Token{
			AccessToken: "access_token",
		}).
		Return(introspection, nil)

	res, err := tokenAuthenticator.AuthenticateKeycloakToken(nil, token)
	if err != nil {
		t.Fatalf("error occurred: %v", err)
	}

	assertTokensAreEqual(t, expectedTokenData, res)
}

func Test_TokenAuthenticator_Authenticate_LooksUpLegacyTokens(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := keycloak.NewMockClient(mockCtrl)
	mockStore := NewMockStorage(mockCtrl)
	tokenAuthenticator := NewTokenAuthenticator(mockKeycloakClient, mockStore, fakeConfig.TokenConfigs)

	subject := "1234567890"
	expiresAt := time.Now().Unix() + 645
	tokenData := &TokenData{
		IsServer:     false,
		UserId:       subject,
		ExpiresAt:    expiresAt,
	}

	token, err := CreateSessionToken(tokenData, fakeConfig.TokenConfigs[0])
	if err != nil {
		t.Fatalf("error occurred: %v", err)
	}

	mockStore.EXPECT().WithContext(gomock.Any()).Return(mockStore)
	mockStore.EXPECT().FindTokenByID(gomock.Eq(token.ID)).Return(token, nil)

	res, err := tokenAuthenticator.Authenticate(nil, token.ID)
	if err != nil {
		t.Fatalf("error occurred: %v", err)
	}

	assertTokensAreEqual(t, tokenData, res)
}
