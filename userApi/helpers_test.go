package userapi

import (
	"net/http"
	"strconv"
	"testing"
)

func Test_tokenDuration(t *testing.T) {

	request, _ := http.NewRequest("GET", "", nil)
	givenDuration := strconv.FormatFloat(float64(10), 'f', -1, 64)

	request.Header.Add(TP_TOKEN_DURATION, givenDuration)

	duration := tokenDuration(request)

	if strconv.FormatFloat(duration, 'f', -1, 64) != givenDuration {
		t.Fatalf("Duration should have been set [%s] but was [%s] ", givenDuration, strconv.FormatFloat(duration, 'f', -1, 64))
	}

}
