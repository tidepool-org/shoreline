module github.com/tidepool-org/shoreline

go 1.15

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/klauspost/compress v1.11.1 // indirect
	github.com/prometheus/client_golang v1.7.1
	github.com/tidepool-org/go-common v0.7.2-0.20201112061205-12377f8c59cb
	github.com/urfave/cli v1.22.4
	go.mongodb.org/mongo-driver v1.4.1
	go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux v0.13.0
	go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo v0.13.0
	go.opentelemetry.io/otel v0.13.0
	go.uber.org/fx v1.13.1
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0 // indirect
	golang.org/x/sync v0.0.0-20200930132711-30421366ff76 // indirect
)
