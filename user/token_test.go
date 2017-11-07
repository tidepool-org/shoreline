package user

import (
	"net/http"
	"strconv"
	"testing"
)

type tokenTestData struct {
	data   *TokenData
	config TokenConfig
}

var tokenConfig = TokenConfig{
	DurationSecs: 3600,
	Secret:       "my secret",
}

func Test_GenerateSessionToken(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 3600},
		config: tokenConfig,
	}

	//given duration seconds trump the configured duration
	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" {
		t.Fatalf("should generate a session token with an ID set")
	}
}

func Test_GenerateSessionToken_DurationFromConfig(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 0},
		config: tokenConfig,
	}
	//given duration seconds trump the configured duration
	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" {
		t.Fatalf("should generate a session token")
	}

	if token.Duration != tokenConfig.DurationSecs {
		t.Fatalf("should use the config duration")
	}
}

func Test_GenerateSessionToken_DurationSecsTrumpConfig(t *testing.T) {

	const fiveSeconds = 5

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: fiveSeconds},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" {
		t.Fatalf("should generate a session token")
	}

	if token.Duration != fiveSeconds {
		t.Fatalf("should use the given duration")
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

	if token.ID == "" {
		t.Fatalf("should generate a session token")
	}

	if token.IsServer == false {
		t.Fatal("should generate a server token")
	}

	if token.Duration != 24*60*60 {
		t.Fatal("the duration should be 24hrs")
	}

}

func Test_extractTokenDuration(t *testing.T) {

	request, _ := http.NewRequest("GET", "", nil)
	givenDuration := strconv.FormatFloat(float64(10), 'f', -1, 64)

	request.Header.Add(TOKEN_DURATION_KEY, givenDuration)

	duration := extractTokenDuration(request)

	if strconv.FormatInt(duration, 10) != givenDuration {
		t.Fatalf("Duration should have been set [%s] but was [%s] ", givenDuration, strconv.FormatInt(duration, 10))
	}
}
