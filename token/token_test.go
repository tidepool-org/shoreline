package token

import (
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" {
		t.Fatalf("should generate a session token with an ID set")
	}

	jwtToken, err := jwt.Parse(token.ID, func(t *jwt.Token) (interface{}, error) { return []byte(testData.config.Secret), nil })
	if err != nil || !jwtToken.Valid {
		t.Fatalf("should decode and validate the token")
	}

	claims := jwtToken.Claims.(jwt.MapClaims)

	if int64(claims["dur"].(float64)) != testData.data.DurationSecs {
		t.Fatalf("token should use the DurationSecs it was given")
	}
	if claims["exp"] == nil {
		t.Fatalf("token expiration should be set")
	}
	if claims["iat"] == nil {
		t.Fatalf("token creation time should be set")
	}
	if claims["jti"] == nil {
		t.Fatalf("token unique id (jti) should be set")
	}

	td, _ := UnpackSessionTokenAndVerify(token.ID, tokenConfig.Secret)

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

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := UnpackSessionTokenAndVerify(token.ID, tokenConfig.Secret)

	if td.DurationSecs != tokenConfig.DurationSecs {
		t.Fatalf("the duration should be from config")
	}
}

func Test_GenerateSessionToken_DurationSecsTrumpConfig(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 5},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := UnpackSessionTokenAndVerify(token.ID, tokenConfig.Secret)

	if td.DurationSecs != testData.data.DurationSecs {
		t.Fatalf("the duration should come from the token data")
	}

}

func Test_GenerateSessionToken_Zendesk_Claims_Patient(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 5000, Audience: "zendesk", Role: "patient"},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	jwtToken, err := jwt.Parse(token.ID, func(t *jwt.Token) (interface{}, error) { return []byte(testData.config.Secret), nil })
	if err != nil || !jwtToken.Valid {
		t.Fatalf("should decode and validate the token")
	}

	claims := jwtToken.Claims.(jwt.MapClaims)

	// check zendesk claims
	if claims["organization"] != "patient" {
		t.Fatalf("the organization should have been set to 'Patient'")
	}
	if claims["tags"] != "patient" {
		t.Fatalf("the tags should have been set to 'Patient'")
	}
	if claims["aud"] != "zendesk" {
		t.Fatalf("the audience should have been set to 'zendesk'")
	}
}

func Test_GenerateSessionToken_Zendesk_Claims_Caregiver(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 5000, Audience: "zendesk", Role: "caregiver"},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	jwtToken, err := jwt.Parse(token.ID, func(t *jwt.Token) (interface{}, error) { return []byte(testData.config.Secret), nil })
	if err != nil || !jwtToken.Valid {
		t.Fatalf("should decode and validate the token")
	}

	claims := jwtToken.Claims.(jwt.MapClaims)

	// check zendesk claims
	if claims["organization"] != "patient" {
		t.Fatalf("the organization should have been set to 'Patient'")
	}
	if claims["tags"] != "patient" {
		t.Fatalf("the tags should have been set to 'Patient'")
	}
	if claims["aud"] != "zendesk" {
		t.Fatalf("the audience should have been set to 'zendesk'")
	}
}

func Test_GenerateSessionToken_Zendesk_Claims_Pro(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 5000, Audience: "zendesk", Role: "hcp"},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	jwtToken, err := jwt.Parse(token.ID, func(t *jwt.Token) (interface{}, error) { return []byte(testData.config.Secret), nil })
	if err != nil || !jwtToken.Valid {
		t.Fatalf("should decode and validate the token")
	}

	claims := jwtToken.Claims.(jwt.MapClaims)

	// check zendesk claims
	if claims["organization"] != "professional" {
		t.Fatalf("the organization should have been set to 'professional'")
	}
	if claims["tags"] != "professional" {
		t.Fatalf("the tags should have been set to 'professional'")
	}
	if claims["aud"] != "zendesk" {
		t.Fatalf("the audience should have been set to 'zendesk'")
	}
}

func Test_GenerateSessionToken_With_UserDetails(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 5000, Email: "user@test.com", Name: "John Doe", Role: "hcp"},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	jwtToken, err := jwt.Parse(token.ID, func(t *jwt.Token) (interface{}, error) { return []byte(testData.config.Secret), nil })
	if err != nil || !jwtToken.Valid {
		t.Fatalf("should decode and validate the token")
	}

	claims := jwtToken.Claims.(jwt.MapClaims)

	if claims["email"] != testData.data.Email {
		t.Fatalf("the email should have been set")
	}
	if claims["name"] != testData.data.Name {
		t.Fatalf("the name should have been set")
	}
	if claims["role"] != testData.data.Role {
		t.Fatalf("the role should have been set")
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

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := UnpackSessionTokenAndVerify(token.ID, tokenConfig.Secret)

	if td.IsServer != true {
		t.Fatal("this should be a server token")
	}

	if td.DurationSecs != 24*60*60 {
		t.Fatal("the duration should be 24hrs")
	}

}

func Test_UnpackedData(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "111", IsServer: true, DurationSecs: 0, Email: "user@test.com", Name: "John Doe", Role: "hcp"},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	data, err := UnpackSessionTokenAndVerify(token.ID, testData.config.Secret)
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

	if data.Email != testData.data.Email {
		t.Fatal("the Email should have been what was given")
	}

	if data.Name != testData.data.Name {
		t.Fatal("the Name should have been what was given")
	}

	if data.Role != testData.data.Role {
		t.Fatal("the Role should have been what was given")
	}

}

func Test_UnpackTokenExpires(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	time.Sleep(2 * time.Second) //ensure token expires

	data, err := UnpackSessionTokenAndVerify(token.ID, testData.config.Secret)

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

	_, err := UnpackSessionTokenAndVerify(token.ID, testData.config.Secret)

	if err != nil {
		t.Fatal("the token should be valid", err.Error())
	}

}

func Test_getUnpackedToken(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, testData.config)

	td, err := UnpackSessionTokenAndVerify(token.ID, testData.config.Secret)
	if err != nil {
		t.Fatal("We should have got TokenData")
	}
	if td.UserId != testData.data.UserId {
		t.Fatalf("got %v expected %v ", td, testData.data)
	}

}
