#!/bin/sh -eu

for D in $(find . -name '*_test.go' ! -path './vendor/*' | xargs dirname | uniq); do
    (cd ${D}; go test -race -v)
done