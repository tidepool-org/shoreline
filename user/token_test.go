package user

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

type tokenTestData struct {
	data   *TokenData
	config TokenConfig
}

var tokenConfig = TokenConfig{
	DurationHours: 24,
	Secret:        "my secret",
}

func Test_GetSessionToken(t *testing.T) {

	tokenString := "123-456-test-token"

	token := GetSessionToken(tokenString)

	if token.Id != tokenString {
		t.Fatalf("session value should have been set for token")
	}
}

func Test_GenerateSessionToken(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 3600},
		config: tokenConfig,
	}

	//given duration seconds trump the configured duration
	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.Id == "" {
		t.Fatalf("should generate a session token with an Id set")
	}

	td, _ := token.unpackToken(tokenConfig.Secret)

	if td.DurationSecs != testData.data.DurationSecs {
		t.Fatalf("we should use the DurationSecs if given")
	}
}

func Test_GenerateSessionToken_DurationFromConfig(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 0},
		config: tokenConfig,
	}

	//given duration seconds trump the configured duration
	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.Id == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := token.unpackToken(tokenConfig.Secret)

	if td.DurationSecs != time.Duration(time.Hour*time.Duration(tokenConfig.DurationHours)).Seconds() {
		t.Fatalf("the duration should be from config")
	}
}

func Test_GenerateSessionToken_DurationSecsTrumpConfig(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 5},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.Id == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := token.unpackToken(tokenConfig.Secret)

	if td.DurationSecs != testData.data.DurationSecs {
		t.Fatalf("the duration should come from the token data")
	}

}

func Test_GenerateSessionToken_NoUserId(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "", IsServer: false, DurationSecs: 3600},
		config: tokenConfig,
	}

	if _, err := CreateSessionToken(testData.data, testData.config); err == nil {
		t.Fatalf("should not generate a session token if there is no userid")
	}
}

func Test_GenerateSessionToken_Server(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "shoreline", IsServer: true, DurationSecs: 0},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.Id == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := token.unpackToken(tokenConfig.Secret)

	if td.IsServer != true {
		t.Fatal("this should be a server token")
	}

	if td.DurationSecs != (time.Hour * 24).Seconds() {
		t.Fatal("the duration should be 24hrs")
	}

}

func Test_UnpackedData(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "111", IsServer: true, DurationSecs: 0},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	data, err := token.UnpackAndVerify(testData.config.Secret)
	if err != nil {
		t.Fatal("unpacked token should be valid", err.Error())
	}

	if data.IsServer == false {
		t.Fatal(" token should have been what was given")
	}

	if data.DurationSecs != testData.data.DurationSecs {
		t.Fatal("the DurationSecs should have been what was given")
	}

	if data.UserId != testData.data.UserId {
		t.Fatal("the user should have been what was given")
	}

}

func Test_UnpackTokenExpires(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	time.Sleep(2 * time.Second) //ensure token expires

	data, err := token.UnpackAndVerify(testData.config.Secret)

	if data != nil {
		t.Fatal("the token should have expired")
	}

	if err == nil {
		t.Fatal("there should be an error for an invalid token")
	}

}

func Test_UnpackAndVerifyStoredToken(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1200},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	data, err := token.UnpackAndVerify(testData.config.Secret)

	if err != nil {
		t.Fatal("the token should be valid", err.Error())
	}

	if data.Valid == false {
		t.Fatal("the token should be valid")
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

	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	td, err := getUnpackedToken(token.Id, testData.config.Secret)
	if err != nil {
		t.Fatal("We should have got TokenData")
	}
	if td.UserId != testData.data.UserId {
		t.Fatalf("got %v expected %v ", td, testData.data)
	}

}

func Test_hasServerToken(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: true, DurationSecs: 1},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if hasServerToken(token.Id, testData.config.Secret) == false {
		t.Fatal("We should have got a server Token")
	}
}

func Test_hasServerToken_false(t *testing.T) {
	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if hasServerToken(token.Id, testData.config.Secret) != false {
		t.Fatal("We should have not got a server Token")
	}
}
