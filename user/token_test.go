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
	DurationSecs: 3600,
	EncodeKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzg3MHpXfMuH4AJ4URtaG4QvZenpfuSz2FmIwdnPEtkrKFmL2
6b89U1tw5WsYAE158znAzPptDA25hAsIcTAqULNsoY3WV2zmsLrUX8pUaCTfExXN
dMFDruR676G3pJWcsI1GuePK5/v3dBHjjTYdtVJiogbCtP+XYT/k1qHZztwRY4oH
Ma8LorxUZco0Mf6qOq5tmRUJhxvCESaqUTpTAIIfByMnPmnIHOHnsYtkiZQBms2x
o1UfpYnqZX2CoN+wPoMoSAlRbnOmmHYbbMFVPNTj7NINwVb8K8iDU7lFR+JfN3UG
lErVo7XCDQcbwTpiZbdj9zWSWbYtIBNBqkNxxwIDAQABAoIBAG3IMhmVlh6BAGYr
0vfO8nvSmWNE8d0yFEbmt5VUptjMzhDRV2ZAascPr/27akU3AiNRgOR1BEZoxY+R
ZUUQ+WqXvefxLuLTdbFxSRdkMEZwZp2/fwCWu53hw5IK4lIBGEOEccs2j3O77iJc
KZWh4IArzbsvyOswRhIdPaoQ/3/TECPa5AXY7LAEj32XfP3K08rRAldgdfTv6XbV
e/pzKMzqgPMIhZ3mG1n7CJ+DLhajEEG36KwszI6OttkjzyBzlsQb3rskEOypG3ZU
k24B++v3Cm7FN0vG+FLFVzwS5rDrF+CUIFCyQU/nAB8nmkiNdCbDI0/614NeSSnE
BZc6G1ECgYEA/zVJdpRx5kgFDyxmJrdVcXJ/digGDct6og0pffcJW1ygBnt+tLRd
gpH+oBNUMz92GKb+wTTlOba0CNbJULM1sZklf604yzpIDji0HyI2oZ0fo+OEkpBz
PyNrdnm2WXF4e3WCb1ehkxGMyfTH70RFKqmPRMka1xWAMXPgbP5Osj8CgYEAzrF3
iAX+geyqagzQfbt5bf9zePmL4Dx6J37pgtZSo88sqtSU6+eYQsF/pS5KrtxD6Sql
5qSbfKekmDhEF4DMUeva76JHmPIPdJH+fPyw6jOB6S3tS+i41S2CGNub1RLz7LCj
NEZ9H5GBVmxBTdiZL3aZWgIxo63Nl0H39k6+TnkCgYEA44Nkx5LU659+6yUAuDku
seGKIhLSOtAQtpEXUVW/ALTVcJH9xikZSALRRXGV2c4UgSu25xU52Ta4zzxz4j6x
em92D5mkjQCbJhqE8VB19aP2hguZr3OZWktATTF6T8ipyR5cNtifkVXO9mgDKZnq
M3tP3tmN1Ps0+mE8TM51588CgYBZYgtz6kuued8UL2h2Bv2zINYZyajAlsaoj8yB
hReFuVDyqy2feq6wp6cAkq0/QwenLIdD34lR9dlK7oIbu9ofzyQFnyLhNESUv5HT
ER+cmBuk7/R/cCuGHMD26PlRwnlzsMtTDuyLG0xYSEZRWMqd6ObWMr6urrmKoL+P
Z2wK2QKBgQC7SZ47YM45pz23yjyrKx6dUAfw5imb6ylZPft24A+W2tFanfRDQITX
wGHgJHaV+gd52zrP6s8AKzMjMcRtB0g0CGf5Qe1BHMh89fJsUKToT8L+040kWl/P
upYmRYNT7J2Met0WVB6u6ZDFSMl+CIFLXHGtU47DjGUmQxqmhW8LOg==
-----END RSA PRIVATE KEY-----`,
	DecodeKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzg3MHpXfMuH4AJ4URtaG
4QvZenpfuSz2FmIwdnPEtkrKFmL26b89U1tw5WsYAE158znAzPptDA25hAsIcTAq
ULNsoY3WV2zmsLrUX8pUaCTfExXNdMFDruR676G3pJWcsI1GuePK5/v3dBHjjTYd
tVJiogbCtP+XYT/k1qHZztwRY4oHMa8LorxUZco0Mf6qOq5tmRUJhxvCESaqUTpT
AIIfByMnPmnIHOHnsYtkiZQBms2xo1UfpYnqZX2CoN+wPoMoSAlRbnOmmHYbbMFV
PNTj7NINwVb8K8iDU7lFR+JfN3UGlErVo7XCDQcbwTpiZbdj9zWSWbYtIBNBqkNx
xwIDAQAB
-----END PUBLIC KEY-----`,
	Audience: "localhost",
	Issuer:   "localhsot",
}

func Test_GenerateSessionToken(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 3600},
		config: tokenConfig,
	}

	//given duration seconds trump the configured duration
	token, _ := CreateSessionToken(testData.data, tokenConfig)

	if token.ID == "" {
		t.Fatalf("should generate a session token with an ID set")
	}

	td, _ := UnpackSessionTokenAndVerify(token.ID, tokenConfig)

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
	token, _ := CreateSessionToken(testData.data, tokenConfig)

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := UnpackSessionTokenAndVerify(token.ID, tokenConfig)

	if td.DurationSecs != tokenConfig.DurationSecs {
		t.Fatalf("the duration should be from config")
	}
}

func Test_GenerateSessionToken_DurationSecsTrumpConfig(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 5},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, tokenConfig)

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := UnpackSessionTokenAndVerify(token.ID, tokenConfig)

	if td.DurationSecs != testData.data.DurationSecs {
		t.Fatalf("the duration should come from the token data")
	}

}

func Test_GenerateSessionToken_NoUserId(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "", IsServer: false, DurationSecs: 3600},
		config: tokenConfig,
	}

	if _, err := CreateSessionToken(testData.data, tokenConfig); err == nil {
		t.Fatalf("should not generate a session token if there is no userid")
	}
}

func Test_GenerateSessionToken_Server(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "shoreline", IsServer: true, DurationSecs: 0},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, tokenConfig)

	if token.ID == "" || token.Time == 0 {
		t.Fatalf("should generate a session token")
	}

	td, _ := UnpackSessionTokenAndVerify(token.ID, tokenConfig)

	if td.IsServer != true {
		t.Fatal("this should be a server token")
	}

	if td.DurationSecs != 24*60*60 {
		t.Fatal("the duration should be 24hrs")
	}

}

func Test_UnpackedData(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "111", IsServer: true, DurationSecs: 0},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, tokenConfig)

	data, err := UnpackSessionTokenAndVerify(token.ID, tokenConfig)
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

	token, _ := CreateSessionToken(testData.data, tokenConfig)

	time.Sleep(2 * time.Second) //ensure token expires

	data, err := UnpackSessionTokenAndVerify(token.ID, tokenConfig)

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

	token, _ := CreateSessionToken(testData.data, tokenConfig)

	_, err := UnpackSessionTokenAndVerify(token.ID, tokenConfig)

	if err != nil {
		t.Fatal("the token should be valid", err.Error())
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

func Test_getUnpackedToken(t *testing.T) {

	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, tokenConfig)

	td, err := UnpackSessionTokenAndVerify(token.ID, tokenConfig)
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

	token, _ := CreateSessionToken(testData.data, tokenConfig)

	if hasServerToken(token.ID, tokenConfig) == false {
		t.Fatal("We should have got a server Token")
	}
}

func Test_hasServerToken_false(t *testing.T) {
	testData := tokenTestData{
		data:   &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1},
		config: tokenConfig,
	}

	token, _ := CreateSessionToken(testData.data, tokenConfig)

	if hasServerToken(token.ID, tokenConfig) != false {
		t.Fatal("We should have not got a server Token")
	}
}
