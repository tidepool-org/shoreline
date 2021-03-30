package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"github.com/mdblp/shoreline/token"
)

const (
	testServiceSecret = "shhhhh"
)

func setUnpackSessionTokenAndVerify(tokenData *token.TokenData, err error) {
	unpackToken = func(id string, secret string) (*token.TokenData, error) { return tokenData, err }
}

func TestNewAuthService(t *testing.T) {
	auth, err := NewAuthService(&Config{
		ServiceSecret: testServiceSecret,
	})
	if err != nil {
		t.Errorf("Failed creating service with error[%v]", err)
	}
	if auth.config.ServiceSecret != testServiceSecret {
		t.Errorf("Unexpected secret configured found:%v, expected:%v",
			auth.config.ServiceSecret,
			testServiceSecret,
		)
	}

	auth, err = NewAuthService(nil)
	if err == nil {
		t.Error("An error should be raised when no config is passed")
	}
	if err.Error() != errorNoConfig {
		t.Errorf("Unexpected error message found:%v, expected:%v",
			err.Error(),
			errorNoConfig,
		)
	}

}

func TestAuthenticate(t *testing.T) {
	auth, err := NewAuthService(&Config{
		ServiceSecret: testServiceSecret,
	})
	if err != nil {
		t.Errorf("Failed creating service with error[%v]", err)
	}
	testToken := "1234"
	tknData := token.TokenData{}
	setUnpackSessionTokenAndVerify(&tknData, nil)
	tkn, err2 := auth.Authenticate(testToken)
	if err2 != nil {
		t.Errorf("Authenticate should not fail, error:%v", err2)
	}
	if *tkn != tknData {
		t.Error("Unexpected token returned")
	}

}

func getGinContext(testToken string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Set(token.TP_SESSION_TOKEN, testToken)
	return c, w
}

func assertAuthMiddlewareResponse(t *testing.T, tknData *token.TokenData,
	authorizeUnverified bool, auth *LocalAuth, c *gin.Context, w *httptest.ResponseRecorder) {
	setUnpackSessionTokenAndVerify(tknData, nil)
	middleware := auth.AuthMiddleware(authorizeUnverified)
	middleware(c)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, c.GetString("userId"), tknData.UserId)
	assert.Equal(t, c.GetBool("isPatient"), tknData.Role == "patient")
	assert.Equal(t, c.GetBool("isCaregiver"), tknData.Role == "caregiver")
	assert.Equal(t, c.GetBool("isHCP"), tknData.Role == "hcp")
	assert.Equal(t, c.GetBool("isServer"), tknData.IsServer)
}
func assertAuthMiddlewareErrorResponse(t *testing.T, tknData *token.TokenData,
	tknError error, authorizeUnverified bool, auth *LocalAuth, c *gin.Context, w *httptest.ResponseRecorder) {
	setUnpackSessionTokenAndVerify(tknData, tknError)
	middleware := auth.AuthMiddleware(authorizeUnverified)
	middleware(c)
	assert.Equal(t, 401, w.Code)
}
func TestAuthMiddleware_withUnverifiedToken(t *testing.T) {
	auth, err := NewAuthService(&Config{
		ServiceSecret: testServiceSecret,
	})
	if err != nil {
		t.Errorf("Failed creating service with error[%v]", err)
	}
	testToken := "1234"
	tknData := token.TokenData{
		UserId:   "1234",
		Role:     "patient",
		IsServer: false,
	}

	c, w := getGinContext(testToken)
	assertAuthMiddlewareResponse(t, &tknData, true, auth, c, w)

	tknData.Role = "caregiver"
	assertAuthMiddlewareResponse(t, &tknData, true, auth, c, w)

	tknData.Role = "hcp"
	assertAuthMiddlewareResponse(t, &tknData, true, auth, c, w)

	tknData.Role = ""
	tknData.IsServer = true
	assertAuthMiddlewareResponse(t, &tknData, true, auth, c, w)

	tknData.Role = "unverified"
	tknData.IsServer = false
	assertAuthMiddlewareResponse(t, &tknData, true, auth, c, w)

	assertAuthMiddlewareErrorResponse(t, nil, errors.New(""), true, auth, c, w)

}

func TestAuthMiddleware_withoutUnverifiedToken(t *testing.T) {
	auth, err := NewAuthService(&Config{
		ServiceSecret: testServiceSecret,
	})
	if err != nil {
		t.Errorf("Failed creating service with error[%v]", err)
	}
	testToken := "1234"
	tknData := token.TokenData{
		UserId:   "1234",
		Role:     "patient",
		IsServer: false,
	}

	c, w := getGinContext(testToken)
	assertAuthMiddlewareResponse(t, &tknData, false, auth, c, w)

	tknData.Role = "caregiver"
	assertAuthMiddlewareResponse(t, &tknData, false, auth, c, w)

	tknData.Role = "hcp"
	assertAuthMiddlewareResponse(t, &tknData, false, auth, c, w)

	tknData.Role = ""
	tknData.IsServer = true
	assertAuthMiddlewareResponse(t, &tknData, false, auth, c, w)

	tknData.Role = "unverified"
	tknData.IsServer = false
	assertAuthMiddlewareErrorResponse(t, &tknData, nil, false, auth, c, w)

	assertAuthMiddlewareErrorResponse(t, nil, errors.New(""), false, auth, c, w)
}
