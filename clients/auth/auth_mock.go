package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mdblp/shoreline/token"
)

type LocalAuthMock struct {
	Token      token.TokenData
	Authorized bool
}

func (l *LocalAuthMock) Authenticate(sessionToken string) (*token.TokenData, error) {
	if l.Authorized {
		return &l.Token, nil
	}
	return nil, errors.New("Not authorized")

}

func (l *LocalAuthMock) AuthMiddleware(authorizeUnverified bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token, err := l.Authenticate(""); err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
		} else if token.Role == "unverified" && !authorizeUnverified {
			c.AbortWithError(http.StatusUnauthorized, errors.New("Unverified user is not authorized"))
		} else {
			c.Set("userId", token.UserId)
			c.Set("isPatient", token.Role == "patient")
			c.Set("isCaregiver", token.Role == "caregiver")
			c.Set("isHCP", token.Role == "hcp")
			c.Set("isServer", token.IsServer)
		}
		c.Next()
	}
}
