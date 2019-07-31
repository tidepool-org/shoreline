#!/bin/sh -eu

rm -rf dist
mkdir dist
go build -mod=vendor -o dist/shoreline shoreline.go
go build -mod=vendor -o dist/user-roles tools/user-roles.go
cp start.sh dist/
cp env.sh dist/
