package main

import (
	"./api"
	sc "./clients"
	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/hakken"
	"github.com/tidepool-org/go-common/clients/mongo"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

type (
	Config struct {
		clients.Config
		Service disc.ServiceListing  `json:"service"`
		Mongo   mongo.Config         `json:"mongo"`
		Api     api.Config           `json:"shoreline"`
		Mail    sc.SesNotifierConfig `json:"sesEmail"`
	}
)

func main() {
	var config Config

	if err := common.LoadConfig([]string{"./config/env.json", "./config/server.json"}, &config); err != nil {
		log.Panic("Problem loading config", err)
	}

	/*
	 * Hakken setup
	 */
	hakkenClient := hakken.NewHakkenBuilder().
		WithConfig(&config.HakkenConfig).
		Build()

	if err := hakkenClient.Start(); err != nil {
		log.Fatal(err)
	}
	defer hakkenClient.Close()

	/*
	 * Shoreline setup
	 */
	store := sc.NewMongoStoreClient(&config.Mongo)
	mail := sc.NewSesNotifier(&config.Mail)

	rtr := mux.NewRouter()
	api := api.InitApi(config.Api, store, mail)
	api.SetHandlers("", rtr)

	/*
	 * Serve it up and publish
	 */
	done := make(chan bool)
	server := common.NewServer(&http.Server{
		Addr:    config.Service.GetPort(),
		Handler: rtr,
	})

	var start func() error
	if config.Service.Scheme == "https" {
		sslSpec := config.Service.GetSSLSpec()
		start = func() error { return server.ListenAndServeTLS(sslSpec.CertFile, sslSpec.KeyFile) }
	} else {
		start = func() error { return server.ListenAndServe() }
	}
	if err := start(); err != nil {
		log.Fatal(err)
	}

	hakkenClient.Publish(&config.Service)

	signals := make(chan os.Signal, 40)
	signal.Notify(signals)
	go func() {
		for {
			sig := <-signals
			log.Printf("Got signal [%s]", sig)

			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				server.Close()
				done <- true
			}
		}
	}()

	<-done

}
