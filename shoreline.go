package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/gorilla/mux"

	"github.com/Shopify/sarama"
	"github.com/cloudevents/sdk-go/protocol/kafka_sarama/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	common "github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/hakken"
	"github.com/tidepool-org/go-common/clients/highwater"
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/shoreline/user"
	"github.com/tidepool-org/shoreline/user/marketo"
)

var (
	marketoConfig = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "tidepool_shoreline_marketo_config_valid",
		Help: "Indicates if the latest shoreline marketo configuration is valid.",
	})
)

type (
	Config struct {
		clients.Config
		Service disc.ServiceListing `json:"service"`
		Mongo   mongo.Config        `json:"mongo"`
		User    user.ApiConfig      `json:"user"`
	}
)

func kafkaSender() *kafka_sarama.Sender {
	topics, _ := os.LookupEnv("KAFKA_TOPIC")
	broker, _ := os.LookupEnv("KAFKA_BROKERS")

	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V2_0_0_0

	sender, err := kafka_sarama.NewSender([]string{broker}, saramaConfig, topics)
	if err != nil {
		log.Printf("failed to create protocol: %s", err.Error())
	}
	return sender
}
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
	config.User.Marketo.ID, _ = os.LookupEnv("MARKETO_ID")
	config.User.Marketo.URL, _ = os.LookupEnv("MARKETO_URL")
	config.User.Marketo.Secret, _ = os.LookupEnv("MARKETO_SECRET")
	config.User.Marketo.ClinicRole, _ = os.LookupEnv("MARKETO_CLINIC_ROLE")
	config.User.Marketo.PatientRole, _ = os.LookupEnv("MARKETO_PATIENT_ROLE")

	unParsedTimeout, found := os.LookupEnv("MARKETO_TIMEOUT")
	if found {
		parsedTimeout64, err := strconv.ParseInt(unParsedTimeout, 10, 32)
		parsedTimeout := uint(parsedTimeout64)
		if err != nil {
			logger.Println(err)
		}
		config.User.Marketo.Timeout = parsedTimeout
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

	highwater := highwater.NewHighwaterClientBuilder().
		WithHostGetter(config.HighwaterConfig.ToHostGetter(hakkenClient)).
		WithHttpClient(httpClient).
		WithConfig(&config.HighwaterConfig.HighwaterClientConfig).
		Build()

	rtr := mux.NewRouter()

	/*
	 * User-Api setup
	 */

	var marketoManager marketo.Manager
	if err := config.User.Marketo.Validate(); err != nil {
		logger.Println("WARNING: Marketo config is invalid", err)
	} else {
		logger.Print("initializing marketo manager")
		marketoManager, _ = marketo.NewManager(logger, config.User.Marketo)
		marketoConfig.Set(1)
	}

	clientStore := user.NewMongoStoreClient(&config.Mongo)
	defer clientStore.Disconnect()
	clientStore.EnsureIndexes()

	userapi := user.InitApi(config.User, logger, clientStore, highwater, marketoManager, kafkaSender())
	defer userapi.Sender.Close(context.Background())
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
	 * Serve it up and publish
	 */
	done := make(chan bool)
	logger.Print("creating http server")
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

	logger.Print("starting http server")
	if err := start(); err != nil {
		logger.Fatal(err)
	}

	hakkenClient.Publish(&config.Service)

	logger.Print("listenting for signals")

	signals := make(chan os.Signal, 40)
	signal.Notify(signals)
	go func() {
		for {
			sig := <-signals
			logger.Printf("Got signal [%s]", sig)

			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				server.Close()
				done <- true
			}
		}
	}()

	<-done

}
