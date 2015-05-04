package common

import (
	"log"
)

func LogLine(file, msg string) {
	log.Println(file + " " + msg)
}

func LogFormated(file, msg string, details ...string) {
	log.Printf(file+" "+msg, details)
}
