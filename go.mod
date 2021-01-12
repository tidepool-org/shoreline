module github.com/mdblp/shoreline

go 1.15

replace github.com/tidepool-org/shoreline => ./

replace github.com/tidepool-org/go-common => github.com/mdblp/go-common v0.6.2

require (
	github.com/SpeakData/minimarketo v0.0.0-20170821092521-29339e452f44
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/codegangsta/cli v1.20.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.3
	github.com/prometheus/client_golang v1.4.1
	github.com/swaggo/swag v1.6.9
	github.com/tidepool-org/go-common v0.0.0-00010101000000-000000000000
	github.com/tidepool-org/shoreline v0.0.0-00010101000000-000000000000
	go.mongodb.org/mongo-driver v1.4.0
)
