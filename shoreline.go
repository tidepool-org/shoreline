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
		log.Panic("Problem loading config", err)
	}

	rtr := mux.NewRouter()
	api := api.InitApi(sc.NewMockStoreClient(), config.Service, rtr)
	api.SetHandlers()

	http.Handle("/", rtr)

	log.Println("Listening...")
	http.ListenAndServe(":3005", nil)

}
