package api

import (
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
