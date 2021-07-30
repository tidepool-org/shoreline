module github.com/mdblp/shoreline

go 1.15

replace github.com/mdblp/shoreline => ./

replace github.com/tidepool-org/go-common => github.com/mdblp/go-common v0.6.2

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/codegangsta/cli v1.20.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.3
	github.com/go-playground/assert/v2 v2.0.1
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/prometheus/client_golang v1.11.0
	github.com/swaggo/swag v1.6.9
	github.com/tidepool-org/go-common v0.0.0-00010101000000-000000000000
	gitlab.com/msvechla/mux-prometheus v0.0.2
	go.mongodb.org/mongo-driver v1.4.0
)
