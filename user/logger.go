package user

import (
	"log"
	"os"
)

var logger = log.New(os.Stdout, "api/user ", log.LstdFlags|log.Lshortfile)
