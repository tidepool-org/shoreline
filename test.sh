#!/bin/sh -eu

go test $(go list ./... | grep -v /vendor/)
