package oauth2

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/RangelReale/osin"
	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/shoreline"
)

type (
	ApiConfig struct {
		ExpireDays int `json:"expireDays"`
	}
	Api struct {
		oauthServer *osin.Server
		storage     *OAuthStorage
		userApi     shoreline.Client
		permsApi    clients.Gatekeeper
		ApiConfig
	}
	//scope that maps to a tidepool permisson
	scope struct {
		name, requestMsg, grantMsg string
	}
	details map[string]interface{}
)

var (
	//Available scopes's
	scopeView   scope = scope{name: "view", requestMsg: "Requests uploading of data on behalf", grantMsg: "Allow uploading of data on your behalf"}
	scopeUpload scope = scope{name: "upload", requestMsg: "Requests viewing of data on behalf", grantMsg: "Allow viewing of data on your behalf"}
)

const (
	//errors
	error_signup_details           = "sorry but look like something was wrong with your signup details!"
	error_signup_pw_match          = "sorry but your passwords don't match"
	error_signup_account           = "sorry but there was an issue creating an account for your oauth2 user"
	error_signup_account_duplicate = "sorry but there is already an account with those details"
	error_generic                  = "sorry but there setting up your account, please contact support@tidepool.org"
	error_check_tidepool_creds     = "sorry but there was an issue authorizing your tidepool user, are your credentials correct?"
	error_applying_permissons      = "sorry but there was an issue apply the permissons for your tidepool user"
	error_oauth_service            = "sorry but there was an issue with our OAuth service"
	//user message
	msg_signup_complete             = "Your Tidepool developer account has been created"
	msg_signup_save_details         = "Please save these details"
	msg_tidepool_account_access     = "Login to grant access to Tidepool"
	msg_tidepool_permissons_granted = "With access to your Tidepool account %s can:"
	//form text
	btn_authorize            = "Grant access to Tidepool"
	btn_no_authorize         = "Deny access to Tidepool"
	btn_signup               = "Signup"
	placeholder_email        = "Email"
	placeholder_pw           = "Password"
	placeholder_pw_confirm   = "Confirm Password"
	placeholder_redirect_uri = "Application redirect_uri"
	placeholder_name         = "Application Name"

	oneDayInSecs = 86400
	//TODO: get prefix from router??
	authPostAction = "/oauth/authorize?response_type=%s&client_id=%s&state=%s&scope=%s&redirect_uri=%s"
	//TODO: stop gap for styling
	btnCss   = "input[type=submit]{background:#0b9eb3;color:#fff;}"
	inputCss = "input{width:80%%;height:37px;margin:5px;font-size:18px;}"
	mfwCss   = "body{margin:40px auto;max-width:650px;line-height:1.6;font-size:18px;color:#444;padding:0 10px}h1,h2,h3{line-height:1.2}"
	basicCss = "<style type=\"text/css\"></style>"
)

func InitApi(
	config ApiConfig,
	storage *OAuthStorage,
	userApi shoreline.Client,
	permsApi clients.Gatekeeper) *Api {

	log.Print("Api setting up ...")

	sconfig := osin.NewServerConfig()
	sconfig.AllowGetAccessRequest = true
	sconfig.AllowClientSecretInParams = true

	return &Api{
		storage:     storage,
		oauthServer: osin.NewServer(sconfig, storage),
		userApi:     userApi,
		permsApi:    permsApi,
		ApiConfig:   config,
	}
}

func (o *Api) SetHandlers(prefix string, rtr *mux.Router) {

	log.Print("Api attaching handlers ...")

	rtr.HandleFunc(prefix+"/signup", o.showSignup).Methods("GET")
	rtr.HandleFunc(prefix+"/signup", o.processSignup).Methods("POST")
	rtr.HandleFunc(prefix+"/authorize", o.showAuthorize).Methods("GET")
	rtr.HandleFunc(prefix+"/authorize", o.processAuthorize).Methods("POST")
	rtr.HandleFunc(prefix+"/token", o.token).Methods("GET")
	rtr.HandleFunc(prefix+"/info", o.info).Methods("GET")

}

func makeScopeOption(theScope scope) string {
	//disabled and selected by default at this stage
	selected := "checked"
	disabled := "return false"
	return fmt.Sprintf("<input type=\"checkbox\" name=\"%s\"  value=\"%s\" %s onclick=\"%s\" /> %s", theScope.name, theScope.name, theScope.requestMsg, selected, disabled)
}

//check we have all the fields we require
func signupFormValid(formData url.Values) (string, bool) {

	if formData.Get("password") != formData.Get("password_confirm") {
		return error_signup_pw_match, false
	}

	if formData.Get("usr_name") != "" &&
		formData.Get("password") != "" &&
		formData.Get("email") != "" &&
		formData.Get("uri") != "" {
		return "", true
	}

	return error_signup_details, false
}

//return requested scope as a comma seperated list
func selectedScopes(formData url.Values) string {

	scopes := []string{}

	if formData.Get(scopeView.name) != "" {
		scopes = append(scopes, scopeView.name)
	}
	if formData.Get(scopeUpload.name) != "" {
		scopes = append(scopes, scopeUpload.name)
	}

	return strings.Join(scopes, ",")
}

func getAllScopes() string {
	return fmt.Sprintf("%s,%s", scopeView.name, scopeUpload.name)
}

//wrapper to write error and display to the user
func writeError(w http.ResponseWriter, errorMessage string, statusCode int) {
	w.WriteHeader(statusCode)
	w.Write([]byte("<html><body>"))
	w.Write([]byte("<i>" + errorMessage + "</i>"))
	w.Write([]byte("</body></html>"))
	return
}

//attach basic styles to the rendered components
func applyStyle(w http.ResponseWriter) {
	style := fmt.Sprintf("<head><style type=\"text/css\">%s%s%s</style></head>", mfwCss, inputCss, btnCss)
	w.Write([]byte(style))
}

// Apply the requested permissons for the app on authorizing users account
func (o *Api) applyPermissons(authorizingUserId, appUserId, scope string) bool {

	log.Printf("applyPermissons: raw scope asked for %s", scope)

	var empty struct{}
	scopes := strings.Split(scope, ",")
	permsToApply := make(clients.Permissions)

	for i := range scopes {
		permsToApply[scopes[i]] = empty
	}

	log.Printf("applyPermissons: permissons to apply %v", permsToApply)

	if appliedPerms, err := o.permsApi.SetPermissions(appUserId, authorizingUserId, permsToApply); err != nil {
		log.Printf("applyPermissons: err %v setting the permissons %v", err, appliedPerms)
		return false
	}
	log.Printf("applyPermissons: permissons %v set", permsToApply)
	return true
}

// Show the signup from so an external user can signup to the tidepool platform
func (o *Api) showSignup(w http.ResponseWriter, r *http.Request) {

	//TODO: as a template
	w.Write([]byte("<html>"))
	applyStyle(w)
	w.Write([]byte("<body>"))
	w.Write([]byte("<h2>Tidepool developer account signup</h2>"))
	w.Write([]byte("<form action=\"\" method=\"POST\">"))
	w.Write([]byte("<fieldset>"))
	w.Write([]byte("<h4>Application Information:</h4>"))
	w.Write([]byte(fmt.Sprintf("<input type=\"text\" name=\"usr_name\" placeholder=\"%s\" /><br/>", placeholder_name)))
	w.Write([]byte(fmt.Sprintf("<input type=\"text\" name=\"uri\" placeholder=\"%s\" /><br/>", placeholder_redirect_uri)))
	w.Write([]byte("<ol>"))
	w.Write([]byte("<li>" + scopeView.requestMsg + " </li>"))
	w.Write([]byte("<li>" + scopeUpload.requestMsg + " </li>"))
	w.Write([]byte("</ol>"))
	//TODO: enable the ability to choose but hardcode for now
	//w.Write([]byte(makeScopeOption(scopeUpload) + "<br />"))
	//w.Write([]byte(makeScopeOption(scopeView) + "<br />"))
	w.Write([]byte("<h4>Account Information:</h4>"))
	w.Write([]byte(fmt.Sprintf("<input type=\"email\" name=\"email\" placeholder=\"%s\" /><br/>", placeholder_email)))
	w.Write([]byte(fmt.Sprintf("<input type=\"password\" name=\"password\" placeholder=\"%s\" /><br/>", placeholder_pw)))
	w.Write([]byte(fmt.Sprintf("<input type=\"password\" name=\"password_confirm\" placeholder=\"%s\" /><br/>", placeholder_pw_confirm)))
	w.Write([]byte(fmt.Sprintf("<input type=\"submit\" value=\"%s\"/>", btn_signup)))
	w.Write([]byte("</fieldset>"))
	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))
}

//Process signup for the app user
func (o *Api) processSignup(w http.ResponseWriter, r *http.Request) {
	applyStyle(w)

	r.ParseForm()

	validationMsg, formValid := signupFormValid(r.Form)

	if formValid {

		if signupResp, err := o.userApi.Signup(r.Form.Get("usr_name"), r.Form.Get("password"), r.Form.Get("email")); err != nil {
			log.Printf("processSignup: error[%s] status[%s]", error_signup_account, err.Error())
			writeError(w, error_signup_account, http.StatusInternalServerError)
		} else {
			secret, _ := GenerateHash(signupResp.UserID, r.Form.Get("uri"), time.Now().String())

			theClient := &osin.DefaultClient{
				Id:          signupResp.UserID,
				Secret:      secret,
				RedirectUri: r.Form.Get("uri"),
				UserData:    map[string]interface{}{"AppName": signupResp.UserName},
			}

			authData := &osin.AuthorizeData{
				Client:      theClient,
				Scope:       getAllScopes(),
				RedirectUri: theClient.RedirectUri,
				ExpiresIn:   int32(o.ApiConfig.ExpireDays * oneDayInSecs),
				CreatedAt:   time.Now(),
			}

			// generate token code
			code, err := o.oauthServer.AuthorizeTokenGen.GenerateAuthorizeToken(authData)
			if err != nil {
				log.Print("processSignup: err[%s]", err.Error())
				writeError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			authData.Code = code

			log.Printf("processSignup: AuthorizeData %v", authData)
			if saveErr := o.storage.SaveAuthorize(authData); saveErr != nil {
				log.Printf("processSignup: error during SaveAuthorize: %s", saveErr.Error())
				writeError(w, error_generic, http.StatusInternalServerError)
			}

			if setErr := o.storage.SetClient(theClient.Id, theClient); setErr != nil {
				log.Printf("signup error during SetClient: %s", setErr.Error())
				writeError(w, error_generic, http.StatusInternalServerError)
			}
			log.Print("processSignup: about to announce the details")
			//Inform of the results
			signedUpIdMsg := fmt.Sprintf("client_id=%s", theClient.Id)
			signedUpSecretMsg := fmt.Sprintf("client_secret=%s", theClient.Secret)
			//TODO: as a template
			w.Write([]byte("<html>"))
			applyStyle(w)
			w.Write([]byte("<body>"))
			w.Write([]byte("<h2>" + msg_signup_complete + "</h2>"))
			w.Write([]byte("<p>" + msg_signup_save_details + "</p>"))

			w.Write([]byte(signedUpIdMsg + " <br/>"))
			w.Write([]byte(signedUpSecretMsg + " <br/>"))
			w.Write([]byte("</html></body>"))

			log.Printf("processSignup: complete [%v] [%s] [%s] ", authData.Client, signedUpIdMsg, signedUpSecretMsg)
		}
	} else if formValid == false {
		log.Printf("processSignup: error[%s]", validationMsg)
		writeError(w, validationMsg, http.StatusBadRequest)
	}
}

//Start the authorize process showing the Tidepool login form to the user
func (o *Api) showAuthorize(w http.ResponseWriter, r *http.Request) {

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	log.Print("showAuthorize: off to handle auth request via oauthServer")

	if ar := o.oauthServer.HandleAuthorizeRequest(resp, r); ar != nil {
		log.Print("showAuthorize: show the login")
		o.showLogin(ar, w, r)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Printf("showAuthorize: stink bro it's all gone pete tong error[%s] code[%d] ", resp.InternalError.Error(), resp.StatusCode)
		//writeError(w, resp.InternalError.Error(), resp.StatusCode)
	}
	osin.OutputJSON(resp, w, r)
}

//Process the authorization request for the Tidepool user
func (o *Api) processAuthorize(w http.ResponseWriter, r *http.Request) {
	applyStyle(w)

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	log.Print("processAuthorize: off to handle auth request via oauthServer")
	if ar := o.oauthServer.HandleAuthorizeRequest(resp, r); ar != nil {
		log.Print("processAuthorize: lets do the user login")

		if loggedInId := o.doLogin(ar, w, r); loggedInId == "" {
			log.Print("processAuthorize: " + error_check_tidepool_creds)
			//we don't give any other details from the platform
			o.showLogin(ar, w, r)
			writeError(w, error_check_tidepool_creds, http.StatusUnauthorized)
		} else {
			log.Print("processAuthorize: user logged in so applying permissons on user")
			log.Printf("Request %v", ar)

			if o.applyPermissons(loggedInId, ar.Client.GetId(), ar.Scope) {
				log.Printf("processAuthorize: apply permissons[%s] to userid[%s]", ar.Scope, loggedInId)
				ar.Authorized = true
				o.oauthServer.FinishAuthorizeRequest(resp, r, ar)
			} else {
				log.Printf("processAuthorize: error[%s]", error_applying_permissons)
				writeError(w, error_applying_permissons, http.StatusInternalServerError)
			}
		}
	}
	if resp.IsError && resp.InternalError != nil {
		log.Printf("processAuthorize: error[%s] status[%d]", resp.InternalError.Error(), resp.StatusCode)
		//writeError(w, resp.InternalError.Error(), resp.StatusCode)
	}
	//TODO: sort this out
	givenCode := fmt.Sprintf("code=%s", resp.Output["code"])
	givenState := fmt.Sprintf("state=%s", resp.Output["state"])
	log.Printf("processAuthorize: resp code[%s] state[%s] ", givenCode, givenState)
	w.Write([]byte(givenCode + " <br/>"))
	w.Write([]byte(givenState + " <br/>"))
	osin.OutputJSON(resp, w, r)
}

//show the login form for authorization
func (o *Api) showLogin(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) {
	//TODO: as a template
	ud := ar.Client.GetUserData().(map[string]interface{})

	w.Write([]byte("<html>"))
	applyStyle(w)
	w.Write([]byte("<body>"))
	w.Write([]byte("<h2>" + msg_tidepool_account_access + "</h2>"))
	w.Write([]byte("<b>" + fmt.Sprintf(msg_tidepool_permissons_granted, ud["AppName"]) + "</b>"))
	w.Write([]byte(fmt.Sprintf("<form action="+authPostAction+" method=\"POST\">",
		ar.Type, ar.Client.GetId(), ar.State, ar.Scope, url.QueryEscape(ar.RedirectUri))))
	//TODO: defaulted at this stage for initial implementation e.g. strings.Contains(ar.Scope, scopeView.name)
	w.Write([]byte("<ol>"))
	w.Write([]byte("<li>" + scopeView.grantMsg + " </li>"))
	w.Write([]byte("<li>" + scopeUpload.grantMsg + " </li>"))
	w.Write([]byte("</ol>"))
	w.Write([]byte(fmt.Sprintf("<input type=\"text\" name=\"login\" placeholder=\"%s\" /><br/>", placeholder_email)))
	w.Write([]byte(fmt.Sprintf("<input type=\"password\" name=\"password\" placeholder=\"%s\" /><br/>", placeholder_pw)))
	w.Write([]byte(fmt.Sprintf("<input type=\"submit\" value=\"%s\"/>", btn_authorize)))
	//TODO allow them to deny
	//w.Write([]byte(fmt.Sprintf("<input type=\"submit\" value=\"%s\"/>", btn_no_authorize)))
	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))
}

//process the login form
func (o *Api) doLogin(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) string {
	log.Print("processLogin: do the login")
	r.ParseForm()

	log.Printf("form data %s %s", r.Form.Get("login"), r.Form.Get("password"))

	if r.Form.Get("login") != "" && r.Form.Get("password") != "" {
		log.Print("processLogin: about to login to the platform")
		if usr, _, err := o.userApi.Login(r.Form.Get("login"), r.Form.Get("password")); err != nil {
			log.Printf("processLogin: err during account login: %s", err.Error())
		} else if err == nil && usr == nil {
			log.Print("processLogin: no user was found")
		} else if usr != nil {
			log.Printf("processLogin: tidepool login success for userid[%s] ", usr.UserID)
			return usr.UserID
		}
	}
	return ""
}

// Access token endpoint
func (o *Api) token(w http.ResponseWriter, r *http.Request) {

	log.Print("token: getting token")
	applyStyle(w)

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	if ar := o.oauthServer.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		o.oauthServer.FinishAccessRequest(resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Printf("token: error[%s] status[%d]", resp.InternalError.Error(), resp.StatusCode)
		//TODO: sort out error's seems to always be 200
		//writeError(w, resp.InternalError.Error(), resp.StatusCode)
	}
	osin.OutputJSON(resp, w, r)
}

// Information endpoint
func (o *Api) info(w http.ResponseWriter, r *http.Request) {

	log.Print("Api: info")
	applyStyle(w)

	resp := o.oauthServer.NewResponse()
	defer resp.Close()

	if ir := o.oauthServer.HandleInfoRequest(resp, r); ir != nil {
		o.oauthServer.FinishInfoRequest(resp, r, ir)
	}
	osin.OutputJSON(resp, w, r)
}
