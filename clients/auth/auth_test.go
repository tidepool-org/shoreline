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

func TestAuthMiddleware(t *testing.T) {
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

	setUnpackSessionTokenAndVerify(&tknData, nil)
	c, w := getGinContext(testToken)
	middleware := auth.AuthMiddleware()
	middleware(c)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, c.GetString("userId"), tknData.UserId)
	assert.Equal(t, c.GetBool("isPatient"), true)
	assert.Equal(t, c.GetBool("isCaregiver"), false)
	assert.Equal(t, c.GetBool("isHCP"), false)
	assert.Equal(t, c.GetBool("isServer"), false)

	tknData.Role = "caregiver"
	setUnpackSessionTokenAndVerify(&tknData, nil)
	middleware = auth.AuthMiddleware()
	middleware(c)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, c.GetString("userId"), tknData.UserId)
	assert.Equal(t, c.GetBool("isPatient"), false)
	assert.Equal(t, c.GetBool("isCaregiver"), true)
	assert.Equal(t, c.GetBool("isHCP"), false)
	assert.Equal(t, c.GetBool("isServer"), false)

	tknData.Role = "hcp"
	setUnpackSessionTokenAndVerify(&tknData, nil)
	middleware = auth.AuthMiddleware()
	middleware(c)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, c.GetString("userId"), tknData.UserId)
	assert.Equal(t, c.GetBool("isPatient"), false)
	assert.Equal(t, c.GetBool("isCaregiver"), false)
	assert.Equal(t, c.GetBool("isHCP"), true)
	assert.Equal(t, c.GetBool("isServer"), false)

	tknData.Role = ""
	tknData.IsServer = true
	setUnpackSessionTokenAndVerify(&tknData, nil)
	middleware = auth.AuthMiddleware()
	middleware(c)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, c.GetString("userId"), tknData.UserId)
	assert.Equal(t, c.GetBool("isPatient"), false)
	assert.Equal(t, c.GetBool("isCaregiver"), false)
	assert.Equal(t, c.GetBool("isHCP"), false)
	assert.Equal(t, c.GetBool("isServer"), true)

	setUnpackSessionTokenAndVerify(nil, errors.New(""))
	middleware = auth.AuthMiddleware()
	middleware(c)
	assert.Equal(t, 401, w.Code)

}
