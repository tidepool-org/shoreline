#!/bin/sh -eu

rm -rf dist
mkdir dist

echo "Build shoreline"
go build -o dist/shoreline shoreline.go
go build -o dist/user-roles tools/user-roles.go
cp start.sh dist/
cp env.sh dist/
