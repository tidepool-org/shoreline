package main

import (
	// "crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"

	"github.com/tidepool-org/go-common"
	// "github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	// "github.com/tidepool-org/go-common/clients/hakken"
	// "github.com/tidepool-org/go-common/clients/highwater"
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/shoreline/oauth2"
	"github.com/tidepool-org/shoreline/user"
)

type (
	Config struct {
		// clients.Config
		Service disc.ServiceListing `json:"service"`
		Mongo   mongo.Config        `json:"mongo"`
		User    user.ApiConfig      `json:"user"`
		Oauth2  oauth2.ApiConfig    `json:"oauth2"`
	}
)

const (
	shoreline_service_prefix = "shoreline "
)

func main() {
	var config Config

	if err := common.LoadConfig([]string{"./config/env.json", "./config/server.json"}, &config); err != nil {
		log.Panic(shoreline_service_prefix, "Problem loading config", err)
	}

	config.Mongo.ConnectionString = os.Getenv("MONGO_CONNECTION_STRING")

	// /*
	//  * Hakken setup
	//  */
	// hakkenClient := hakken.NewHakkenBuilder().
	// 	WithConfig(&config.HakkenConfig).
	// 	Build()
	//
	// if err := hakkenClient.Start(); err != nil {
	// 	log.Fatal(shoreline_service_prefix, err)
	// }
	// defer hakkenClient.Close()

	/*
	 * Clients
	 */

	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	//
	// httpClient := &http.Client{Transport: tr}

	// highwater := highwater.NewHighwaterClientBuilder().
	// 	WithHostGetter(config.HighwaterConfig.ToHostGetter(hakkenClient)).
	// 	WithHttpClient(httpClient).
	// 	WithConfig(&config.HighwaterConfig.HighwaterClientConfig).
	// 	Build()

	rtr := mux.NewRouter()

	/*
	 * User-Api setup
	 */

	log.Print(shoreline_service_prefix, "adding", user.USER_API_PREFIX)

	userapi := user.InitApi(config.User, user.NewMongoStoreClient(&config.Mongo), nil)
	userapi.SetHandlers("", rtr)

	// /*
	//  * Oauth setup
	//  */
	//
	// userClient := user.NewUserClient(userapi)
	//
	// permsClient := clients.NewGatekeeperClientBuilder().
	// 	WithHostGetter(config.GatekeeperConfig.ToHostGetter(hakkenClient)).
	// 	WithHttpClient(httpClient).
	// 	WithTokenProvider(userClient).
	// 	Build()
	//
	// log.Print(shoreline_service_prefix, "adding", oauth2.OAUTH2_API_PREFIX)
	//
	// oauthapi := oauth2.InitApi(config.Oauth2, oauth2.NewOAuthStorage(&config.Mongo), userClient, permsClient)
	// oauthapi.SetHandlers("", rtr)
	//
	// oauthClient := oauth2.NewOAuth2Client(oauthapi)
	//
	// log.Print(shoreline_service_prefix, oauth2.OAUTH2_API_PREFIX, "adding oauthClient")
	// userapi.AttachOauth(oauthClient)

	/*
	 * Serve it up and publish
	 */
	done := make(chan bool)
	server := common.NewServer(&http.Server{
		Addr:    config.Service.Host,
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
		log.Fatal(shoreline_service_prefix, err)
	}

	// hakkenClient.Publish(&config.Service)

	signals := make(chan os.Signal, 40)
	signal.Notify(signals)
	go func() {
		for {
			sig := <-signals
			log.Printf(shoreline_service_prefix+"Got signal [%s]", sig)

			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				server.Close()
				done <- true
			}
		}
	}()

	<-done

}
