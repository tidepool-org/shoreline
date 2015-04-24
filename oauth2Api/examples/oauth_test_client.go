package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/RangelReale/osin"
)

type (
	OAuthClient struct{}
)

func main() {

	log.Print("InitOAuthClient setting up ...")

	client := &OAuthClient{}

	http.HandleFunc("/client/appauth/code", client.code)
	http.HandleFunc("/client/app", client.app)

	http.ListenAndServe(":14000", nil)
}

func (o *OAuthClient) code(w http.ResponseWriter, r *http.Request) {

	log.Print("OAuthClient: code")

	r.ParseForm()

	log.Printf("OAuthClient: all form data %v", r.Form)

	code := r.Form.Get("code")

	log.Printf("OAuthClient: code from form %s", code)

	w.Write([]byte("<html><body>"))
	w.Write([]byte("APP AUTH - CODE<br/>"))
	defer w.Write([]byte("</body></html>"))

	if code == "" {
		w.Write([]byte("What what - no code so nothing to do"))
		return
	}

	jr := make(map[string]interface{})

	// build access code url
	aurl := fmt.Sprintf("/oauth/v1/token?grant_type=authorization_code&client_id=ff2245581b&client_secret=c68768e60d41f8ad3bdaef987db3330b3de60d10&redirect_uri=%s&code=%s",
		url.QueryEscape("http://localhost:14000/client/appauth/code"), url.QueryEscape(code))

	log.Printf("OAuthClient: auth url %s", aurl)

	// if parse, download and parse json
	if r.Form.Get("doparse") == "1" {
		err := downloadAccessToken(fmt.Sprintf("http://localhost:8009%s", aurl),
			&osin.BasicAuth{"ff2245581b", "c68768e60d41f8ad3bdaef987db3330b3de60d10"}, jr)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
		}
	}

	log.Printf("OAuthClient: details %v ", jr)

	// show json error
	if erd, ok := jr["error"]; ok {
		w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
	}

	// show json access token
	if at, ok := jr["access_token"]; ok {
		w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
	}

	w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

	// output links
	w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL</a><br/>", aurl)))

	cururl := *r.URL
	curq := cururl.Query()
	curq.Add("doparse", "1")
	cururl.RawQuery = curq.Encode()
	w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))
}

func (o *OAuthClient) app(w http.ResponseWriter, r *http.Request) {
	log.Print("OAuthClient: app login")

	w.Write([]byte("<html><body>"))
	w.Write([]byte(fmt.Sprintf("<a href=\"http://localhost:8009/oauth/v1/authorize?response_type=code&client_id=ff2245581b&redirect_uri=%s\">Tidepool Login</a><br/>", url.QueryEscape("http://localhost:14000/client/appauth/code"))))
	w.Write([]byte("</body></html>"))
}

func downloadAccessToken(url string, auth *osin.BasicAuth, output map[string]interface{}) error {
	// download access token
	preq, err := http.NewRequest("GET", url, nil)
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

	if presp.StatusCode != 200 {
		return errors.New("Invalid status code")
	}

	jdec := json.NewDecoder(presp.Body)
	err = jdec.Decode(&output)
	return err
}
