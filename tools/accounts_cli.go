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

	app.Commands = []cli.Command{

		//e.g. update -e testie@user.org -r clinic
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
					Usage: "the environment we are running against",
				},
			},
			Action: updateAccount,
		},
		//e.g. find -r clinic
		{
			Name:      "find-account",
			ShortName: "fa",
			Usage:     `find an account to be updated`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "email",
					Usage: "eamil address of the account your finding",
				},
				cli.StringFlag{
					Name:  "env",
					Usage: "the environment we are running against",
				},
			},
			Action: findAccount,
		},
		//e.g. find -r clinic
		{
			Name:      "find",
			ShortName: "f",
			Usage:     `find all accounts associated with a specific role`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "role",
					Value: "clinic",
					Usage: "the role that is being given to the user",
				},
				cli.StringFlag{
					Name:  "env",
					Usage: "the environment we are running against",
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
	} else if targetEnv == "stg" {
		return stg_host
	}
	return local_host
}

func (a *admin) login() {

	urlPath := a.env + "/auth/serverlogin"

	un := "hydrophone-local"
	pw := os.Getenv("SERVER_SECRET")

	if un == "" || pw == "" {
		log.Fatal("username or password not set")
	}

	req, _ := http.NewRequest("POST", urlPath, nil)
	req.Header.Add(tp_server_name, un)
	req.Header.Add(tp_server_secret, pw)

	res, err := a.client.Do(req)
	if err != nil {
		log.Fatal(fmt.Sprint("Login request failed", err.Error()))
	}

	switch res.StatusCode {
	case 200:
		a.token = res.Header.Get(tp_token)
		return
	default:
		log.Fatal(fmt.Sprint("Login failed", res.StatusCode))
		return
	}
}

func findAccounts(c *cli.Context) {

	hostEnv := setHost(c.String("env"))

	adminUser := &admin{env: hostEnv, client: &http.Client{}}
	adminUser.login()

	roles := []byte(fmt.Sprintf(`{"roles":["%s"]}`, c.String("role")))

	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/auth/users", hostEnv), bytes.NewBuffer(roles))
	req.Header.Add(tp_token, adminUser.token)

	res, err := adminUser.client.Do(req)

	if err != nil {
		log.Println("Error finding accounts ", err.Error())
		return
	}

	switch res.StatusCode {
	case 200:
		data, _ := ioutil.ReadAll(res.Body)
		var raw []interface{}
		json.Unmarshal(data, &raw)

		log.Println("accounts:")
		for i := range raw {
			log.Printf("user: %v\n", raw[i])
		}
		return
	default:
		log.Println("Failed finding profiles", res.StatusCode)
		return
	}
}

func findAccount(c *cli.Context) {

	hostEnv := setHost(c.String("env"))
	email := strings.TrimSpace(c.String("email"))

	adminUser := &admin{env: hostEnv, client: &http.Client{}}
	adminUser.login()

	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/auth/user/%s", hostEnv, email), nil)
	req.Header.Add(tp_token, adminUser.token)

	res, err := adminUser.client.Do(req)

	if err != nil {
		log.Println("Error trying to find user to update ", err.Error())
		return
	}

	switch res.StatusCode {
	case 200:
		data, _ := ioutil.ReadAll(res.Body)
		var raw map[string]interface{}
		json.Unmarshal(data, &raw)
		log.Printf("\nusername: %s \nuserid: %s", raw["username"], raw["userid"])
		return
	default:
		log.Printf("Finding user %s account failed with %s", email, res.Status)
		return
	}
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

	roles := []byte(fmt.Sprintf(`{"updates":{"roles":["%s"]}}`, c.String("role")))

	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/auth/user/%s", hostEnv, userid), bytes.NewBuffer(roles))
	req.Header.Add(tp_token, adminUser.token)

	log.Println("update req", req.URL)

	res, err := adminUser.client.Do(req)

	if err != nil {
		log.Println("Error trying to apply update ", err.Error())
		return
	}

	log.Println("Account roles update status ", res.Status)

	switch res.StatusCode {
	case 200:
		return
	default:
		log.Println("Account update failed", res.Status)
		return
	}
}
