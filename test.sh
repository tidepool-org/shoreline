#!/bin/sh -eu
go get -u github.com/jstemmer/go-junit-report
go test -v -race ./... 2>&1 | go-junit-report  > test-report.xml