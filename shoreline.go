package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"go.uber.org/fx"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/label"
	"go.opentelemetry.io/otel/propagators"

	"github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/configuration"
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/go-common/clients/shoreline"
	"github.com/tidepool-org/go-common/events"
	cloudevents "github.com/tidepool-org/go-common/events"
	"github.com/tidepool-org/go-common/tracing"
	"github.com/tidepool-org/shoreline/user"
)

//mongoProvider provide mongo configuration
func mongoProvider() mongo.Config {
	var c mongo.Config
	c.FromEnv()
	return c
}

//configProvider read config
func configProvider() user.ApiConfig {
	var c user.ApiConfig

	c.TokenConfigs = make([]user.TokenConfig, 2)

	current := &c.TokenConfigs[0]
	current.EncodeKey = os.Getenv("PRIVATE_KEY")
	current.DecodeKey = os.Getenv("PUBLIC_KEY")
	current.Algorithm = "RS256"
	current.Audience = os.Getenv("API_HOST")
	current.Issuer = os.Getenv("API_HOST")
	current.DurationSecs = 60 * 60 * 24 * 30

	previous := &c.TokenConfigs[1]
	previous.EncodeKey = os.Getenv("PREVIOUS_PRIVATE_KEY")
	previous.DecodeKey = os.Getenv("PREVIOUS_PUBLIC_KEY")
	previous.Algorithm = "RS256"
	previous.Audience = os.Getenv("PREVIOUS_API_HOST")
	previous.Issuer = os.Getenv("PREVIOUS_API_HOST")
	previous.DurationSecs = 60 * 60 * 24 * 30

	c.ServerSecret = os.Getenv("SERVER_SECRET")
	c.LongTermKey = os.Getenv("LONG_TERM_KEY")
	c.VerificationSecret = os.Getenv("VERIFICATION_SECRET")
	c.ClinicDemoUserID = os.Getenv("DEMO_CLINIC_USER_ID")
	c.Salt = os.Getenv("SALT")
	c.LongTermDaysDuration = 30
	return c
}

// mongoClientStoreProvider provides a Mongo Client Store
func mongoClientStoreProvider(m mongo.Config) user.Storage {
	return user.NewMongoStoreClient(&m)
}

//StoreIndexer creates indexes in the background
func StoreIndexer(clientStore user.Storage, lifecycle fx.Lifecycle) {
	ctx, cancel := context.WithCancel(context.Background())
	ensureIndexesCtx := otel.ContextWithBaggageValues(ctx,
		label.String("service", "shoreline"),
		label.String("function", "clientStore.EnsureIndexes"))

	disconnectCtx := otel.ContextWithBaggageValues(ctx,
		label.String("service", "shoreline"),
		label.String("function", "clientStore.Disconnect"))

	lifecycle.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				// blocks until context is terminated
				clientStore.EnsureIndexes(ensureIndexesCtx)
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			cancel()
			return clientStore.Disconnect(disconnectCtx)
		},
	})
}

func eventHandlerProvider(clientStore user.Storage) (events.EventHandler, error) {
	userEventsHandlerCtx := otel.ContextWithBaggageValues(context.Background(),
		label.String("service", "shoreline"),
		label.String("function", "user.NewUserEventsHandler"))
	handler, err := user.NewUserEventsHandler(clientStore, userEventsHandlerCtx)
	return events.NewUserEventsHandler(handler), err
}

func loggerProvider() *log.Logger {
	return log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
}

func routerProvider(api *user.Api) *mux.Router {
	rtr := mux.NewRouter()
	rtr.Use(otelmux.Middleware("shoreline", otelmux.WithPropagators(otel.NewCompositeTextMapPropagator(propagators.TraceContext{}, propagators.Baggage{}))))
	api.SetHandlers("", rtr)
	return rtr
}

func serverProvider(config configuration.InboundConfig, rtr *mux.Router) *common.Server {
	return common.NewServer(&http.Server{
		Addr:    config.ListenAddress,
		Handler: rtr,
	})
}

func startService(server *common.Server, config configuration.InboundConfig, lifecycle fx.Lifecycle) {

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				var start func() error
				if config.Protocol == "https" {
					start = func() error { return server.ListenAndServeTLS(config.SslCertFile, config.SslKeyFile) }
				} else {
					start = func() error { return server.ListenAndServe() }
				}
				if err := start(); err != nil {
					return err
				}

				return nil
			},
			OnStop: func(ctx context.Context) error {
				return server.Close()
			},
		},
	)
}

func main() {
	//sarama.Logger = log.New(ioutil.Discard, "[Sarama] ", log.LstdFlags)

	fx.New(
		tracing.TracingModule,
		fx.Provide(
			events.CloudEventsConfigProvider,
			events.CloudEventsConsumerProvider,
			eventHandlerProvider,
		),
		clients.SeagullModule,
		clients.GatekeeperModule,
		shoreline.ShorelineModule,
		configuration.Module,
		fx.Provide(
			routerProvider,
			loggerProvider,
			mongoProvider,
			configProvider,
			mongoClientStoreProvider,
			serverProvider,
			user.NewUserEventsNotifier,
			user.InitApi,
		),
		fx.Invoke(tracing.StartTracer, StoreIndexer, cloudevents.StartEventConsumer, startService),
	).Run()
}
