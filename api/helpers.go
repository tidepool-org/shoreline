package api

import (
	"net/http"
	"net/url"
)

func HasParams(query url.Values, params []string) bool {
	var ok bool

	for i := range params {

		_, ok = query[params[i]]

		if ok == false {
			return ok
		}
	}
	return ok
}

func GetSessionToken(header http.Header) string {
	return header.Get("x-tidepool-session-token")
}
