package user

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

type tokenTestData struct {
	data       *TokenData
	secretUsed string
}

func Test_GetSessionToken(t *testing.T) {

	tokenString := "123-456-test-token"

	token := GetSessionToken(tokenString)

	if token.Id != tokenString {
		t.Fatalf("session value should have been set for token")
	}
}

func Test_GenerateSessionTokenWhenNoUserId(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "", IsServer: false, DurationSecs: 3600}, secretUsed: "my secret"}

	if _, err := CreateSessionToken(testData.data, testData.secretUsed); err == nil {
		t.Fatalf("should not generate a session token if there is no userid")
	}
}

func Test_GenerateSessionToken(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 3600}, secretUsed: "my secret"}

	if token, _ := CreateSessionToken(testData.data, testData.secretUsed); token.Id == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

}

func Test_GenerateSessionTokenForServer(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "shoreline", IsServer: true, DurationSecs: 3600}, secretUsed: "my secret"}

	if token, _ := CreateSessionToken(testData.data, testData.secretUsed); token.Id == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

}

func Test_UnpackedData(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "111", IsServer: true, DurationSecs: 3600}, secretUsed: "my other secret"}

	token, _ := CreateSessionToken(testData.data, testData.secretUsed)

	if data := token.UnpackAndVerify(testData.secretUsed); data == nil {
		t.Fatalf("unpacked token should be valid")
	} else {

		if data.IsServer == false {
			t.Fatalf(" token should have been what was given")
		}

		if data.DurationSecs != testData.data.DurationSecs {
			t.Fatalf("the DurationSecs should have been what was given")
		}

		if data.UserId != testData.data.UserId {
			t.Fatalf("the user should have been what was given")
		}
	}

}

func Test_UnpackTokenExpires(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1}, secretUsed: "my secret"}

	token, _ := CreateSessionToken(testData.data, testData.secretUsed)

	time.Sleep(2 * time.Second) //ensure token expires

	if data := token.UnpackAndVerify(testData.secretUsed); data != nil && data.Valid != false {
		t.Fatalf("the token should have expired")
	}

}

func Test_UnpackAndVerifyStoredToken(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1200}, secretUsed: "my secret"}

	token, _ := CreateSessionToken(testData.data, testData.secretUsed)

	if data := token.UnpackAndVerify(testData.secretUsed); data != nil && data.Valid == false {
		t.Fatalf("the token should not have expired")
	}
}

func Test_extractTokenDuration(t *testing.T) {

	request, _ := http.NewRequest("GET", "", nil)
	givenDuration := strconv.FormatFloat(float64(10), 'f', -1, 64)

	request.Header.Add(TOKEN_DURATION_KEY, givenDuration)

	duration := extractTokenDuration(request)

	if strconv.FormatFloat(duration, 'f', -1, 64) != givenDuration {
		t.Fatalf("Duration should have been set [%s] but was [%s] ", givenDuration, strconv.FormatFloat(duration, 'f', -1, 64))
	}

}

func Test_getUnpackedToken(t *testing.T) {
	testData := tokenTestData{data: &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1}, secretUsed: "my secret"}

	token, _ := CreateSessionToken(testData.data, testData.secretUsed)

	if td := getUnpackedToken(token.Id, testData.secretUsed); td == nil {
		t.Fatal("We should have got TokenData")
	} else {
		if td.UserId != testData.data.UserId {
			t.Fatalf("got %v expected %v ", td, testData.data)
		}
	}
}

func Test_hasServerToken(t *testing.T) {
	testData := tokenTestData{data: &TokenData{UserId: "2341", IsServer: true, DurationSecs: 1}, secretUsed: "my secret"}
	token, _ := CreateSessionToken(testData.data, testData.secretUsed)

	if hasServerToken(token.Id, testData.secretUsed) == false {
		t.Fatal("We should have got a server Token")
	}
}

func Test_hasServerToken_false(t *testing.T) {
	testData := tokenTestData{data: &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1}, secretUsed: "my secret"}
	token, _ := CreateSessionToken(testData.data, testData.secretUsed)

	if hasServerToken(token.Id, testData.secretUsed) != false {
		t.Fatal("We should have not got a server Token")
	}
}
