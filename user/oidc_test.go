package user

import (
	"errors"
	"net/http"
	"testing"
)

func Test_UpdateUserWithOauth_Error_MissingSessionToken(t *testing.T) {
	response := T_PerformRequest(t, "POST", "/oauth/merge")
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUserWithOauth_Error_TokenError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{nil, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "POST", "/oauth/merge", headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}
