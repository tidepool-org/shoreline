package main

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Shopify/sarama"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
	"go.opentelemetry.io/otel/propagators"

	"github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/hakken"
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/go-common/events"
	"github.com/tidepool-org/shoreline/user"
)

type (
	Config struct {
		clients.Config
		Service disc.ServiceListing `json:"service"`
		Mongo   mongo.Config        `json:"mongo"`
		User    user.ApiConfig      `json:"user"`
	}
)

func main() {
	var config Config
	logger := log.New(os.Stdout, user.USER_API_PREFIX, log.LstdFlags|log.Lshortfile)
	log.SetPrefix(user.USER_API_PREFIX)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := common.LoadEnvironmentConfig([]string{"TIDEPOOL_SHORELINE_ENV", "TIDEPOOL_SHORELINE_SERVICE"}, &config); err != nil {
		logger.Panic("Problem loading Shoreline config", err)
	}

	// server secret may be passed via a separate env variable to accomodate easy secrets injection via Kubernetes
	serverSecret, found := os.LookupEnv("SERVER_SECRET")
	if found {
		config.User.ServerSecret = serverSecret
	}

	config.User.TokenConfigs = make([]user.TokenConfig, 2)

	current := &config.User.TokenConfigs[0]
	privateKey, _ := os.LookupEnv("PRIVATE_KEY")
	publicKey, _ := os.LookupEnv("PUBLIC_KEY")
	apiHost, _ := os.LookupEnv("API_HOST")
	current.EncodeKey = privateKey
	current.DecodeKey = publicKey
	current.Algorithm = "RS256"
	current.Audience = apiHost
	current.Issuer = apiHost
	current.DurationSecs = 60 * 60 * 24 * 30

	previous := &config.User.TokenConfigs[1]
	previousPrivateKey, _ := os.LookupEnv("PREVIOUS_PRIVATE_KEY")
	previousPublicKey, _ := os.LookupEnv("PREVIOUS_PUBLIC_KEY")
	previousApiHost, _ := os.LookupEnv("PREVIOUS_API_HOST")
	previous.EncodeKey = previousPrivateKey
	previous.DecodeKey = previousPublicKey
	previous.Algorithm = "RS256"
	previous.Audience = previousApiHost
	previous.Issuer = previousApiHost
	previous.DurationSecs = 60 * 60 * 24 * 30

	longTermKey, found := os.LookupEnv("LONG_TERM_KEY")
	if found {
		config.User.LongTermKey = longTermKey
	}

	verificationSecret, found := os.LookupEnv("VERIFICATION_SECRET")
	if found {
		config.User.VerificationSecret = verificationSecret
	}
	clinicDemoUserID, found := os.LookupEnv("DEMO_CLINIC_USER_ID")
	if found {
		config.User.ClinicDemoUserID = clinicDemoUserID
	}

	salt, found := os.LookupEnv("SALT")
	if found {
		config.User.Salt = salt
	}

	config.Mongo.FromEnv()

	/*
	 * Hakken setup
	 */
	hakkenClient := hakken.NewHakkenBuilder().
		WithConfig(&config.HakkenConfig).
		Build()

	if !config.HakkenConfig.SkipHakken {
		if err := hakkenClient.Start(); err != nil {
			logger.Fatal(err)
		}
		defer hakkenClient.Close()
	} else {
		logger.Print("skipping hakken service")
	}

	/*
	 * Clients
	 */

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: tr}

	rtr := mux.NewRouter()
	rtr.Use(otelmux.Middleware("shoreline", otelmux.WithPropagators(propagators.TraceContext{}, propagators.Baggage{})))

	/*
	 * User-Api setup
	 */

	clientStore := user.NewMongoStoreClient(&config.Mongo)
	defer clientStore.Disconnect()
	clientStore.EnsureIndexes()

	// Start logging kafka connection debug info
	sarama.Logger = logger

	kafkaConfig := events.NewConfig()
	if err := kafkaConfig.LoadFromEnv(); err != nil {
		log.Fatalln(err)
	}
	notifier, err := user.NewUserEventsNotifier(kafkaConfig)
	if err != nil {
		log.Fatalln(err)
	}
	handler, err := user.NewUserEventsHandler(clientStore)
	if err != nil {
		log.Fatalln(err)
	}
	consumer, err := events.NewSaramaCloudEventsConsumer(kafkaConfig)
	if err != nil {
		log.Fatalln(err)
	}
	consumer.RegisterHandler(events.NewUserEventsHandler(handler))

	// Stop logging kafka connection debug info
	sarama.Logger = log.New(ioutil.Discard, "[Sarama] ", log.LstdFlags)

	logger.Print("creating seagull client")
	seagull := clients.NewSeagullClientBuilder().
		WithHostGetter(disc.NewStaticHostGetterFromString("http://seagull:9120")).
		WithHttpClient(httpClient).
		Build()

	userapi := user.InitApi(config.User, logger, clientStore, notifier, seagull)
	logger.Print("installing handlers")
	userapi.SetHandlers("", rtr)

	userClient := user.NewUserClient(userapi)

	logger.Print("creating gatekeeper client")
	permsClient := clients.NewGatekeeperClientBuilder().
		WithHostGetter(config.GatekeeperConfig.ToHostGetter(hakkenClient)).
		WithHttpClient(httpClient).
		WithTokenProvider(userClient).
		Build()

	userapi.AttachPerms(permsClient)

	/*
	 * Serve it up
	 */
	logger.Print("creating http server")
	server := common.NewServer(&http.Server{
		Addr:    config.Service.GetPort(),
		Handler: rtr,
	})

	logger.Print("starting http server")
	if err := server.ListenAndServe(); err != nil {
		logger.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger.Print("listening for signals")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			sig := <-signals
			logger.Printf("Got signal [%s], terminating ...", sig)
			if err := server.Close(); err != nil {
				log.Printf("Error while stopping http server: %v", err)
			}
			cancel()
		}
	}()

	// blocks until context is canceled right after server.Close()
	if err := consumer.Start(ctx); err != nil {
		log.Printf("Error while starting events consumer: %v", err)
	}
}
