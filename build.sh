#!/bin/sh -eu

rm -rf dist
mkdir dist
export GO111MODULE=on

# generate version number
if [ -n "${TRAVIS_TAG:-}" ]; then
    VERSION_BASE=${TRAVIS_TAG}  
else 
    VERSION_BASE=$(git describe --abbrev=0 --tags 2> /dev/null || echo 'dblp.0.0.0')
fi
VERSION_SHORT_COMMIT=$(git rev-parse --short HEAD)
VERSION_FULL_COMMIT=$(git rev-parse HEAD)

GO_COMMON_PATH="github.com/tidepool-org/go-common"

echo "go vet check"
go vet ./...

echo "Build shoreline $VERSION_BASE+$VERSION_FULL_COMMIT"
go mod tidy
go build -ldflags "-X $GO_COMMON_PATH/clients/version.ReleaseNumber=$VERSION_BASE \
    -X $GO_COMMON_PATH/clients/version.FullCommit=$VERSION_FULL_COMMIT \
    -X $GO_COMMON_PATH/clients/version.ShortCommit=$VERSION_SHORT_COMMIT" \
    -o dist/shoreline shoreline.go

