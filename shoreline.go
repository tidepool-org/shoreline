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

type (
	Config struct {
		Service disc.ServiceListing `json:"service"`
		Mongo   mongo.Config        `json:"mongo"`
	}
)

func main() {
	var config Config

	if err := common.LoadConfig([]string{"./config/env.json", "./config/server.json"}, &config); err != nil {
		log.Panic("Problem loading config", err)
	}

	cfg := api.Config{
		ServerSecret: "shhh! don't tell",
		LongTermKey:  "the longetermkey",
		Salt:         "a mineral substance composed primarily of sodium chloride",
	}

	store := sc.NewMongoStoreClient(&config.Mongo)

	rtr := mux.NewRouter()
	api := api.InitApi(store, cfg, rtr)
	api.SetHandlers()

	http.Handle("/", rtr)

	log.Println("Listening...")
	http.ListenAndServe(":3005", nil)

}
