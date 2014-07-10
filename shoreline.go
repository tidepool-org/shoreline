package main

import (
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/go-common/utilities"
	"log"
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

}
