package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/RangelReale/osin"
)

type (
	OAuthClient struct{ Id, Secret string }
)

const (
	//just so it doesn't look super bad :)
	basicCss    = "<style type=\"text/css\">body{margin:40px auto;max-width:650px;line-height:1.6;font-size:18px;color:#444;padding:0 10px}h1,h2,h3{line-height:1.2}</style>"
	clientUrl   = "http://localhost:14000"
	tidepoolUrl = "http://localhost:8009"
	appauthPath = "/appauth/code"
)

// e.g. go run oauth_test_client.go -client_id=9f265bbf73 -client_secret=6c0efdc2b8e234e8a59c8fda4abb560601bb0387
//
func main() {

	log.Print("Setting up Tidepools OAuth2 test client ...")

	id := flag.String("client_id", "", "your registered client_id")
	secret := flag.String("client_secret", "", "your registered client_secret")

	flag.Parse()

	if *id != "" && *secret != "" {
		client := &OAuthClient{Id: *id, Secret: *secret}

		log.Printf("running for client_id=%s client_secret=%s", client.Id, client.Secret)

		http.HandleFunc(appauthPath, client.code)
		http.HandleFunc("/", client.app)

		log.Printf("go to [%s]", clientUrl)

		http.ListenAndServe(":14000", nil)
	}

	log.Fatalln("Sorry but we need your registered apps client_id and client_secret")

}

func (o *OAuthClient) code(w http.ResponseWriter, r *http.Request) {

	log.Print("OAuthClient: code")

	r.ParseForm()

	log.Printf("OAuthClient: all form data %v", r.Form)

	code := r.Form.Get("code")

	log.Printf("OAuthClient: code from form %s", code)

	w.Write([]byte(fmt.Sprintf("<html><head>%s</head><body>", basicCss)))
	defer w.Write([]byte("</body></html>"))

	if code == "" {
		w.Write([]byte("What what - no code so nothing to do"))
		return
	}

	jr := make(map[string]interface{})

	// build access code url
	tokenUrl := fmt.Sprintf(
		"/auth/oauth2/token?grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=%s&code=%s",
		o.Id,
		o.Secret,
		url.QueryEscape(clientUrl+appauthPath),
		url.QueryEscape(code),
	)

	log.Printf("OAuthClient: auth url %s", tokenUrl)

	// if parse, download and parse json
	if r.Form.Get("doparse") == "1" {

		err := downloadAccessToken(fmt.Sprintf(tidepoolUrl+"%s", tokenUrl), &osin.BasicAuth{o.Id, o.Secret}, jr)
		if err != nil {
			w.Write([]byte("Error downloading token: " + err.Error()))
			w.Write([]byte("<br/>"))
		}
	}

	log.Printf("OAuthClient: details %v ", jr)

	// show json error
	if erd, ok := jr["error"]; ok {
		w.Write([]byte(fmt.Sprintf("An error occurred: %s<br/>\n", erd)))
	}

	// show json access token
	if at, ok := jr["access_token"]; ok {
		w.Write([]byte("<h2>Access Token:</h2>"))
		w.Write([]byte(fmt.Sprintf("%v", at)))
	}

	//show the full result
	if jr["refresh_token"] != nil && jr["access_token"] != nil {
		w.Write([]byte("<h2>Full Result:</h2>"))
		w.Write([]byte(fmt.Sprintf("%v<br/>", jr)))
	}

	// output links
	//w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL</a><br/>", tidepoolUrl+tokenUrl)))

	cururl := *r.URL
	curq := cururl.Query()
	curq.Add("doparse", "1")
	cururl.RawQuery = curq.Encode()
	w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))
}

func (o *OAuthClient) app(w http.ResponseWriter, r *http.Request) {
	log.Print("OAuthClient: app login")

	w.Write([]byte(fmt.Sprintf("<html><head>%s</head><body>", basicCss)))
	w.Write([]byte(fmt.Sprintf(
		"<a href=\"%s/auth/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s\">Tidepool Login</a><br/>",
		tidepoolUrl,
		o.Id,
		url.QueryEscape(clientUrl+appauthPath),
	)))
	w.Write([]byte("</body></html>"))
}

func downloadAccessToken(url string, auth *osin.BasicAuth, output map[string]interface{}) error {
	// download access token
	preq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	if auth != nil {
		preq.SetBasicAuth(auth.Username, auth.Password)
	}

	pclient := &http.Client{}
	presp, err := pclient.Do(preq)
	if err != nil {
		return err
	}

	if presp.StatusCode != http.StatusOK {
		log.Printf("downloadAccessToken: %d", presp.StatusCode)
		return errors.New("Invalid status code")
	}

	jdec := json.NewDecoder(presp.Body)
	err = jdec.Decode(&output)
	return err
}
