// @title Shoreline API
// @version 1.2.0
// @description The purpose of this API is to provide authentication for end users and other tidepool Services
// @license.name BSD 2-Clause "Simplified" License
// @host api.android-qa.your-loops.dev
// @BasePath /auth
// @accept json
// @produce json
// @schemes https

// @securityDefinitions.basic BasicAuth
// @in header
// @name Authorization

// @securityDefinitions.apikey TidepoolAuth
// @in header
// @name x-tidepool-session-token
package main

import (
	"context"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	muxprom "gitlab.com/msvechla/mux-prometheus/pkg/middleware"

	"github.com/mdblp/shoreline/user"

	"github.com/mdblp/go-common/clients/mongo"
)

func main() {
	logger := log.New(os.Stdout, user.USER_API_PREFIX, log.LstdFlags|log.Lshortfile)
	auditLogger := log.New(os.Stdout, user.USER_API_PREFIX, log.LstdFlags)
	// Init random number generator
	rand.Seed(time.Now().UnixNano())

	var mongoConfig mongo.Config

	servicePort := os.Getenv("SHORELINE_PORT")
	if servicePort == "" {
		servicePort = "9107"
	}

	// Instrumentation setup
	instrumentation := muxprom.NewCustomInstrumentation(true, "dblp", "shoreline", prometheus.DefBuckets, nil, prometheus.DefaultRegisterer)

	shorelineConfig := user.NewConfigFromEnv(logger)
	mongoConfig.FromEnv()
	rtr := mux.NewRouter()
	rtr.Use(instrumentation.Middleware)

	/*
	 * User-Api setup
	 */
	storage, err := user.NewStore(&mongoConfig, logger)
	if err != nil {
		logger.Fatal(err)
	}
	defer storage.Close()
	storage.Start()

	userapi := user.New(shorelineConfig, logger, storage, auditLogger)
	logger.Print("Installing handlers")
	userapi.SetHandlers("", rtr)

	/*
	 * Serve it up and publish
	 */
	logger.Printf("Creating http server on 0.0.0.0:%s", servicePort)
	srv := &http.Server{
		Addr:    ":" + servicePort,
		Handler: rtr,
	}

	// Initializing the server in a goroutine so that
	// it won't block the graceful shutdown handling below
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown:", err)
	}

	logger.Println("Server exiting")
}
