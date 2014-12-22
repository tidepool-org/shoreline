package api

import (
	"log"
	"net/http"
	"strconv"
)

const (
	TP_TOKEN_DURATION = "tokenduration"
)

//has a duration been set?
func tokenDuration(req *http.Request) (dur float64) {

	durString := req.Header.Get(TP_TOKEN_DURATION)

	if durString != "" {
		log.Printf("tokenDuration: given duration [%s]", durString)
		dur, _ = strconv.ParseFloat(durString, 64)
	}

	log.Printf("tokenDuration: set to [%f]", dur)

	return dur
}
