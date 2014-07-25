package main

import (
	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/mongo"
	"log"
	"net/http"
)

type Config struct {
	clients.Config
	Service disc.ServiceListing `json:"service"`
	Mongo   mongo.Config        `json:"mongo"`
}

func main() {
	var config Config

	if err := common.LoadConfig([]string{"./config/env.json", "./config/server.json"}, &config); err != nil {
		log.Fatal("Problem loading config", err)
	}

	shoreline := InitApi(clients.NewMockStoreClient())

	rtr := mux.NewRouter()

	rtr.HandleFunc("/user", shoreline.GetUserInfo).Methods("GET")
	rtr.HandleFunc("/user/:userid", shoreline.GetUserInfo).Methods("GET")

	rtr.HandleFunc("/user", shoreline.CreateUser).Methods("POST")
	rtr.HandleFunc("/user", shoreline.UpdateUser).Methods("PUT")
	rtr.HandleFunc("/user/:userid", shoreline.UpdateUser).Methods("PUT")

	rtr.HandleFunc("/login", shoreline.Login).Methods("POST")
	rtr.HandleFunc("/login", shoreline.RefreshSession).Methods("GET")
	rtr.HandleFunc("/login/:longtermkey", shoreline.RefreshSession).Methods("POST")

	rtr.HandleFunc("/serverlogin", shoreline.ServerLogin).Methods("POST")

	rtr.HandleFunc("/token/:token", shoreline.RefreshSession).Methods("GET")

	rtr.HandleFunc("/logout", shoreline.RefreshSession).Methods("POST")

	rtr.HandleFunc("/private", shoreline.AnonymousIdHashPair).Methods("GET")
	rtr.HandleFunc("/private/:userid/:key/", shoreline.ManageIdHashPair).Methods("GET")

	http.Handle("/", rtr)

	log.Println("Listening...")
	http.ListenAndServe(":3005", nil)

	/*
			{ path: '/status', verb: 'get', func: status},

		    { path: '/user', verb: 'post', func: createUser},

		    { path: '/user', verb: 'get', func: getUserInfo},
		    { path: '/user/:userid', verb: 'get', func: getUserInfo },

		    { path: '/user', verb: 'del', func: deleteUser},
		    { path: '/user/:userid', verb: 'del', func: deleteUser },


		    { path: '/user', verb: 'put', func: updateUser},
		    { path: '/user/:userid', verb: 'put', func: updateUser },


		    { path: '/login', verb: 'post', func: [ restify.authorizationParser(), login ] },
		    { path: '/login', verb: 'get', func: refreshSession },

		    { path: '/login/:longtermkey', verb: 'post', func: [ restify.authorizationParser(), validateLongterm, login ] },
		    { path: '/serverlogin', verb: 'post', func: serverLogin },
		    { path: '/token/:token', verb: 'get',
		      func: [requireServerToken, serverCheckToken] },
		    { path: '/logout', verb: 'post', func: logout },
		    { path: '/private', verb: 'get', func: anonymousIdHashPair },

		    { path: '/private/:userid/:key/', verbs: ['get', 'post', 'del', 'put'],
		      func: [requireServerToken, manageIdHashPair]
	*/

}
