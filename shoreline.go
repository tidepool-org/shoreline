package main

import (
	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/shoreline/api"
	sc "github.com/tidepool-org/shoreline/clients"
	"log"
	"net/http"
)

type Config struct {
	Service disc.ServiceListing `json:"service"`
	Mongo   mongo.Config        `json:"mongo"`
}

func main() {
	var config Config

	if err := common.LoadConfig([]string{"./config/env.json", "./config/server.json"}, &config); err != nil {
		log.Fatal("Problem loading config", err)
	}

	log.Printf("mongo %v service %v", config.Mongo, config.Service)

	api := api.InitApi(sc.NewMockStoreClient(), config.Service)

	rtr := mux.NewRouter()

	rtr.HandleFunc("/user", api.GetUserInfo).Methods("GET")
	rtr.HandleFunc("/user/{userid}", api.GetUserInfo).Methods("GET")

	rtr.HandleFunc("/user", api.CreateUser).Methods("POST")
	rtr.HandleFunc("/user", api.UpdateUser).Methods("PUT")
	rtr.HandleFunc("/user/{userid}", api.UpdateUser).Methods("PUT")

	rtr.HandleFunc("/login", api.Login).Methods("POST")
	rtr.HandleFunc("/login", api.RefreshSession).Methods("GET")
	rtr.HandleFunc("/login/{longtermkey}", api.LongtermLogin).Methods("POST")

	rtr.HandleFunc("/serverlogin", api.ServerLogin).Methods("POST")

	rtr.HandleFunc("/token/{token}", api.ServerCheckToken).Methods("GET")

	rtr.HandleFunc("/logout", api.Logout).Methods("POST")

	rtr.HandleFunc("/private", api.AnonymousIdHashPair).Methods("GET")
	rtr.HandleFunc("/private/{userid}/{key}", api.ManageIdHashPair).Methods("GET", "POST", "PUT", "DELETE")

	http.Handle("/", rtr)

	log.Println("Listening...")
	http.ListenAndServe(":3005", nil)

}
