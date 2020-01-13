package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/urfave/cli"

	"github.com/tidepool-org/go-common/clients/shoreline"
)

const (
	TidepoolServerName   = "x-tidepool-server-name"
	TidepoolServerSecret = "x-tidepool-server-secret"
	TidepoolSessionToken = "x-tidepool-session-token"
)

type admin struct {
	client *http.Client
	secret string
	host   string
	token  string
}

func main() {
	app := cli.NewApp()
	app.Name = "User Roles"
	app.Usage = "Manage user roles"
	app.Version = "0.0.1"
	app.Author = "Jamie"
	app.Email = "jamie@tidepool.org"

	const environmentUsage = "Target environment (one of: \"prd\", \"stg\", \"dev\", \"local\")"

	app.Commands = []cli.Command{
		{
			Name:      "find",
			ShortName: "f",
			Usage:     "Find all users assigned a role",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "role",
					Usage: "Role to search for (one of: \"clinic\")",
				},
				cli.StringFlag{
					Name:  "env",
					Usage: environmentUsage,
				},
			},
			Action: findUsersWithRole,
		},
		{
			Name:      "add",
			ShortName: "a",
			Usage:     "Add the specified role to an existing user found by email",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "email",
					Usage: "Email address for the user",
				},
				cli.StringFlag{
					Name:  "role",
					Usage: "Role to add to the user (one of: \"clinic\")",
				},
				cli.StringFlag{
					Name:  "env",
					Usage: environmentUsage,
				},
			},
			Action: addRoleToUser,
		},
		{
			Name:      "remove",
			ShortName: "r",
			Usage:     "Remove the specified role from an existing user found by email",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "email",
					Usage: "Email address for the user",
				},
				cli.StringFlag{
					Name:  "role",
					Usage: "Role to remove from the user (one of: \"clinic\")",
				},
				cli.StringFlag{
					Name:  "env",
					Usage: environmentUsage,
				},
			},
			Action: removeRoleFromUser,
		},
	}

	app.Run(os.Args)
}

func die(err error) {
	fmt.Println("ERROR:", err)
	os.Exit(1)
}

func findUsersWithRole(c *cli.Context) {
	if a, err := NewAdmin(c.String("env")); err != nil {
		die(err)
	} else if users, err := a.GetUsersWithRole(c.String("role")); err != nil {
		die(err)
	} else {
		for _, user := range users {
			dumpUser(&user)
		}
	}
}

func addRoleToUser(c *cli.Context) {
	if updater, err := NewAddUserRoleUpdater(c.String("role")); err != nil {
		die(err)
	} else {
		applyUpdatesToUser(c, []UserUpdater{updater})
	}
}

func removeRoleFromUser(c *cli.Context) {
	if updater, err := NewRemoveUserRoleUpdater(c.String("role")); err != nil {
		die(err)
	} else {
		applyUpdatesToUser(c, []UserUpdater{updater})
	}
}

func applyUpdatesToUser(c *cli.Context, updaters []UserUpdater) {
	if a, err := NewAdmin(c.String("env")); err != nil {
		die(err)
	} else if user, err := a.GetUserByEmail(c.String("email")); err != nil {
		die(err)
	} else if user, err := a.ApplyUpdatesToUser(user, updaters); err != nil {
		die(err)
	} else {
		dumpUser(user)
	}
}

type UserUpdater interface {
	Update(user *shoreline.UserData, updates *shoreline.UserUpdate) error
}

type AddUserRoleUpdater struct {
	role string
}

func NewAddUserRoleUpdater(role string) (*AddUserRoleUpdater, error) {
	if role == "" {
		return nil, errors.New("Role not specified")
	} else {
		return &AddUserRoleUpdater{role: role}, nil
	}
}

func (m *AddUserRoleUpdater) Update(user *shoreline.UserData, updates *shoreline.UserUpdate) error {
	var originalRoles *[]string
	if updates.Roles != nil {
		originalRoles = updates.Roles
	} else if user.Roles != nil {
		originalRoles = &user.Roles
	} else {
		originalRoles = &[]string{}
	}

	for _, role := range *originalRoles {
		if role == m.role {
			return nil
		}
	}

	updatedRoles := append(*originalRoles, m.role)
	updates.Roles = &updatedRoles
	return nil
}

type RemoveUserRoleUpdater struct {
	role string
}

func NewRemoveUserRoleUpdater(role string) (*RemoveUserRoleUpdater, error) {
	if role == "" {
		return nil, errors.New("Role not specified")
	} else {
		return &RemoveUserRoleUpdater{role: role}, nil
	}
}

func (m *RemoveUserRoleUpdater) Update(user *shoreline.UserData, updates *shoreline.UserUpdate) error {
	var originalRoles *[]string
	if updates.Roles != nil {
		originalRoles = updates.Roles
	} else if user.Roles != nil {
		originalRoles = &user.Roles
	} else {
		return nil
	}

	updatedRoles := make([]string, 0)
	for _, role := range *originalRoles {
		if role != m.role {
			updatedRoles = append(updatedRoles, role)
		}
	}

	updates.Roles = &updatedRoles
	return nil
}

func NewAdmin(env string) (*admin, error) {
	if secret := os.Getenv("SERVER_SECRET"); secret == "" {
		return nil, errors.New("Environment variable SERVER_SECRET not specified")
	} else if host, err := envToHost(env); err != nil {
		return nil, err
	} else {
		return &admin{secret: secret, client: &http.Client{}, host: host}, nil
	}
}

func (a *admin) LoginAsServer() error {
	if a.token != "" {
		return nil
	}

	req, err := http.NewRequest("POST", a.urlWithHost("/auth/serverlogin"), nil)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating new server login request: %s", err.Error()))
	}

	req.Header.Add(TidepoolServerName, "USER_ROLES")
	req.Header.Add(TidepoolServerSecret, a.secret)

	res, err := a.client.Do(req)
	if err != nil {
		return errors.New(fmt.Sprintf("Error sending server login request: %s", err.Error()))
	} else if res.StatusCode != http.StatusOK {
		body := &bytes.Buffer{}
		body.ReadFrom(res.Body)
		return errors.New(fmt.Sprintf("Unexpected response status code from server login request: [%d] %s", res.StatusCode, body))
	}

	a.token = res.Header.Get(TidepoolSessionToken)
	if a.token == "" {
		return errors.New("No session token returned from server login request")
	}
	return nil
}

func (a *admin) GetUserByEmail(email string) (*shoreline.UserData, error) {
	if email == "" {
		return nil, errors.New("Email not specified")
	}

	if err := a.LoginAsServer(); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("/auth/user/%s", email)
	req, err := http.NewRequest("GET", a.urlWithHost(url), nil)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error creating new get user request: %s", err.Error()))
	}

	req.Header.Add(TidepoolSessionToken, a.token)

	res, err := a.client.Do(req)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error sending get user request: %s", err.Error()))
	} else if res.StatusCode != http.StatusOK {
		body := &bytes.Buffer{}
		body.ReadFrom(res.Body)
		return nil, errors.New(fmt.Sprintf("Unexpected response status code from get user request: [%d] %s", res.StatusCode, body))
	}

	var user shoreline.UserData
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		return nil, errors.New(fmt.Sprintf("Error decoding JSON from get user request: %s", err.Error()))
	}
	return &user, nil
}

func (a *admin) GetUsersWithRole(role string) ([]shoreline.UserData, error) {
	if role == "" {
		return nil, errors.New("Role not specified")
	}

	if err := a.LoginAsServer(); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("/auth/users?role=%s", url.QueryEscape(role))
	req, err := http.NewRequest("GET", a.urlWithHost(url), nil)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error creating new get users request: %s", err.Error()))
	}

	req.Header.Add(TidepoolSessionToken, a.token)

	res, err := a.client.Do(req)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error sending get users request: %s", err.Error()))
	} else if res.StatusCode != http.StatusOK {
		body := &bytes.Buffer{}
		body.ReadFrom(res.Body)
		return nil, errors.New(fmt.Sprintf("Unexpected response status code from get users request: [%d] %s", res.StatusCode, body))
	}

	var users []shoreline.UserData
	if err := json.NewDecoder(res.Body).Decode(&users); err != nil {
		return nil, errors.New(fmt.Sprintf("Error decoding JSON from get users request: %s", err.Error()))
	}
	return users, nil
}

func (a *admin) ApplyUpdatesToUser(user *shoreline.UserData, updaters []UserUpdater) (*shoreline.UserData, error) {
	if user == nil {
		return nil, errors.New("User not specified")
	}

	if err := a.LoginAsServer(); err != nil {
		return nil, err
	}

	updates := shoreline.UserUpdate{}
	for _, updater := range updaters {
		if err := updater.Update(user, &updates); err != nil {
			return nil, errors.New(fmt.Sprintf("Error updating user: %s", err.Error()))
		}
	}

	if !updates.HasUpdates() {
		return user, nil
	}

	requestBody := &bytes.Buffer{}
	updateRequest := &map[string]shoreline.UserUpdate{"updates": updates}
	if err := json.NewEncoder(requestBody).Encode(updateRequest); err != nil {
		return nil, errors.New(fmt.Sprintf("Error encoding JSON for update user request: %s", err.Error()))
	}

	url := fmt.Sprintf("/auth/user/%s", user.UserID)
	req, err := http.NewRequest("PUT", a.urlWithHost(url), requestBody)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error creating new update user request: %s", err.Error()))
	}

	req.Header.Add(TidepoolSessionToken, a.token)

	res, err := a.client.Do(req)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error sending update user request: %s", err.Error()))
	} else if res.StatusCode != http.StatusOK {
		body := &bytes.Buffer{}
		body.ReadFrom(res.Body)
		return nil, errors.New(fmt.Sprintf("Unexpected response status code from update user request: [%d] %s", res.StatusCode, body))
	}

	if err := json.NewDecoder(res.Body).Decode(user); err != nil {
		return nil, errors.New(fmt.Sprintf("Error decoding JSON from update user request: %s", err.Error()))
	}

	return user, nil
}

func (a *admin) urlWithHost(path string) string {
	return fmt.Sprintf("%s%s", a.host, path)
}

func envToHost(env string) (string, error) {
	switch env {
	case "prd":
		return "https://api.tidepool.org", nil
	case "int":
		return "https://int-api.tidepool.org", nil
	case "stg":
		return "https://stg-api.tidepool.org", nil
	case "dev":
		return "https://dev-api.tidepool.org", nil
	case "dev-clinic":
		return "https://dev-clinic-api.tidepool.org", nil
	case "local":
		return "http://localhost:8009", nil
	case "":
		return "", errors.New("Environment not specified")
	default:
		return "", errors.New(fmt.Sprintf("Invalid environment: %s", env))
	}
}

func dumpUser(user *shoreline.UserData) {
	if dump, err := json.Marshal(user); err != nil {
		fmt.Printf("Error dumping user: %s\n", err.Error())
	} else {
		fmt.Printf("%s\n", dump)
	}
}
