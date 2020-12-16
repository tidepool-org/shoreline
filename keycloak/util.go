package keycloak

import (
	"fmt"
	"github.com/Nerzal/gocloak/v7"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
)

func safePStr(s *string) (result string) {
	if s != nil {
		result = *s
	}
	return
}

func safePBool(s *bool) (result bool) {
	if s != nil {
		result = *s
	}
	return
}

// checkForError Copied from gocloak - used for sending requests to custom endpoints
func checkForError(resp *resty.Response, err error, errMessage string) error {
	if err != nil {
		return &gocloak.APIError{
			Code:    0,
			Message: errors.Wrap(err, errMessage).Error(),
		}
	}

	if resp == nil {
		return &gocloak.APIError{
			Message: "empty response",
		}
	}

	if resp.IsError() {
		var msg string

		if e, ok := resp.Error().(*gocloak.HTTPErrorResponse); ok && e.NotEmpty() {
			msg = fmt.Sprintf("%s: %s", resp.Status(), e)
		} else {
			msg = resp.Status()
		}

		return &gocloak.APIError{
			Code:    resp.StatusCode(),
			Message: msg,
		}
	}

	return nil
}
