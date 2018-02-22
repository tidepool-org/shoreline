package user

import (
	"errors"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/tidepool-org/go-common/tokens"
)

type sessionValidator struct {
	secret string
}

func makeSessionRequest(token string) *http.Request {
	request := &http.Request{Header: http.Header{}}
	request.Header.Set(tokens.TidepoolSessionTokenName, token)
	return request
}

func newSessionValidator(secret string) *sessionValidator {
	return &sessionValidator{secret: secret}
}

func (s *sessionValidator) validate(request *http.Request) (*TokenData, error) {
	sessionToken := request.Header.Get(tokens.TidepoolSessionTokenName)
	jwtToken, err := jwt.Parse(sessionToken, func(t *jwt.Token) ([]byte, error) { return []byte(s.secret), nil })
	if err != nil {
		return nil, err
	}
	if !jwtToken.Valid {
		return nil, errors.New("SessionToken is invalid")
	}

	isServer := jwtToken.Claims["svr"] == "yes"
	durationSecs, ok := jwtToken.Claims["dur"].(int64)
	if !ok {
		durationSecs = int64(jwtToken.Claims["dur"].(float64))
	}
	userID := jwtToken.Claims["usr"].(string)

	return &TokenData{
		IsServer:     isServer,
		DurationSecs: durationSecs,
		UserId:       userID,
		token:        sessionToken,
	}, nil
}
