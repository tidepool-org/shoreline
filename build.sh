#!/bin/sh -eu

rm -rf dist
mkdir dist
export GO111MODULE=on
go build -gcflags="all=-N -l" -o dist/shoreline shoreline.go
go build -o dist/user-roles tools/user-roles.go
cp start.sh dist/
cp env.sh dist/
