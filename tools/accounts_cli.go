package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/codegangsta/cli"
)

const (
	prd_host   = "https://api.tidepool.org"
	stg_host   = "https://stg-api.tidepool.org"
	dev_host   = "https://dev-api.tidepool.org"
	local_host = "http://localhost:8009"

	tp_server_name   = "x-tidepool-server-name"
	tp_server_secret = "x-tidepool-server-secret"
	tp_token         = "x-tidepool-session-token"
)

type admin struct {
	client *http.Client
	token  string
	env    string
}

func main() {

	app := cli.NewApp()

	app.Name = "User Role"
	app.Usage = "Internal tool to add update and find users by role type"
	app.Version = "0.0.1"
	app.Author = "Jamie"
	app.Email = "jamie@tidepool.org"

	const environment_message = "the environment we are running against, options are `prd`, `stg`, `dev` and `local`"

	app.Commands = []cli.Command{

		{
			Name:      "update",
			ShortName: "u",
			Usage:     `update and existing account to have a role`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "userid",
					Usage: "userid of the account your updating",
				},
				cli.StringFlag{
					Name:  "role",
					Value: "clinic",
					Usage: "the role that is being given to the user, defaults to `clinic`",
				},
				cli.StringFlag{
					Name:  "env",
					Usage: environment_message,
				},
			},
			Action: updateAccount,
		},
		{
			Name:      "find-account",
			ShortName: "fa",
			Usage:     `find an account to be updated`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "email",
					Usage: "email address of the account your finding",
				},
				cli.StringFlag{
					Name:  "env",
					Usage: environment_message,
				},
			},
			Action: findAccount,
		},
		{
			Name:      "find",
			ShortName: "f",
			Usage:     "find all accounts associated with a specific role",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "role",
					Value: "clinic",
					Usage: "the role we are searching for",
				},
				cli.StringFlag{
					Name:  "env",
					Usage: environment_message,
				},
			},
			Action: findAccounts,
		},
	}

	app.Run(os.Args)
}

func setHost(targetEnv string) string {

	targetEnv = strings.ToLower(targetEnv)

	fmt.Println("targeting environment ...", targetEnv)

	if targetEnv == "dev" {
		return dev_host
	} else if targetEnv == "prd" {
		return prd_host
	} else if targetEnv == "stg" {
		return stg_host
	} else if targetEnv == "local" {
		return local_host
	}
	log.Fatalf("`%s` is not a valid environment name", targetEnv)
	return ""
}

func (a *admin) login() {

	urlPath := a.env + "/auth/serverlogin"

	un := "hydrophone-local"
	pw := os.Getenv("SERVER_SECRET")

	if un == "" || pw == "" {
		log.Fatal("username or password not set")
	}

	req, err := http.NewRequest("POST", urlPath, nil)

	if err != nil {
		log.Fatal("Error creating the request ", err.Error())
	}

	req.Header.Add(tp_server_name, un)
	req.Header.Add(tp_server_secret, pw)

	res, err := a.client.Do(req)
	if err != nil {
		log.Fatal("Login request failed", err.Error())
	}

	if res.StatusCode == http.StatusOK {
		a.token = res.Header.Get(tp_token)
		return
	}

	log.Fatal("Login failed with status code", res.StatusCode)
	return
}

func findAccounts(c *cli.Context) {

	hostEnv := setHost(c.String("env"))

	adminUser := &admin{env: hostEnv, client: &http.Client{}}
	adminUser.login()

	roles := []byte(fmt.Sprintf(`{"roles":["%s"]}`, strings.ToLower(c.String("role"))))

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/auth/users", hostEnv), bytes.NewBuffer(roles))

	if err != nil {
		log.Fatal("Error creating the request ", err.Error())
	}

	req.Header.Add(tp_token, adminUser.token)

	res, err := adminUser.client.Do(req)

	if err != nil {
		log.Println("Error finding accounts ", err.Error())
		return
	}

	if res.StatusCode == http.StatusOK {
		data, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal("Error reading the resp body ", err.Error())
			return
		}
		var raw []interface{}
		json.Unmarshal(data, &raw)

		log.Println("accounts:")
		for i := range raw {
			log.Printf("user: %v\n", raw[i])
		}
		return
	}

	log.Println("Failed finding profiles", res.StatusCode)
	return

}

func findAccount(c *cli.Context) {

	hostEnv := setHost(c.String("env"))
	email := strings.TrimSpace(c.String("email"))

	adminUser := &admin{env: hostEnv, client: &http.Client{}}
	adminUser.login()

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/auth/user/%s", hostEnv, email), nil)
	if err != nil {
		log.Fatal("Error creating the request ", err.Error())
		return
	}
	req.Header.Add(tp_token, adminUser.token)

	res, err := adminUser.client.Do(req)

	if err != nil {
		log.Println("Error trying to find user to update ", err.Error())
		return
	}

	if res.StatusCode == http.StatusOK {
		data, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal("Error reading the resp body ", err.Error())
		}
		var raw map[string]interface{}
		json.Unmarshal(data, &raw)
		log.Printf("\nusername: %s \nuserid: %s", raw["username"], raw["userid"])
	}

	log.Printf("Finding user %s account failed with %s", email, res.Status)
	return
}

func updateAccount(c *cli.Context) {

	hostEnv := setHost(c.String("env"))
	userid := strings.TrimSpace(c.String("userid"))

	if userid == "" {
		log.Fatal("userid not set for the account we are applying the role too")
		return
	}

	adminUser := &admin{env: hostEnv, client: &http.Client{}}
	adminUser.login()

	roles := []byte(fmt.Sprintf(`{"updates":{"roles":["%s"]}}`, strings.ToLower(c.String("role"))))

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/auth/user/%s", hostEnv, userid), bytes.NewBuffer(roles))
	if err != nil {
		log.Fatal("Error creating the request ", err.Error())
	}
	req.Header.Add(tp_token, adminUser.token)

	res, err := adminUser.client.Do(req)

	if err != nil {
		log.Println("Error trying to apply update ", err.Error())
		return
	}

	log.Println("Account roles update status ", res.Status)

	if res.StatusCode == http.StatusOK {
		return
	}

	log.Println("Account update failed", res.Status)
	return

}
