#!/bin/sh -eu

rm -rf dist
mkdir dist
go get gopkg.in/mgo.v2
go build -o dist/shoreline shoreline.go
go build -o dist/user-roles tools/user-roles.go
cp start.sh dist/
cp env.sh dist/
