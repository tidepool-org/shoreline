shoreline
=========

[![Build Status](https://travis-ci.com/tidepool-org/shoreline.png)](https://travis-ci.com/tidepool-org/shoreline)

Shoreline is the entrance to the ocean; in our case it manages logins and user accounts

## Building

### As part of the platform

If you are running Shoreline as part of [runservers](http://developer.tidepool.io/starting-up-services/ 'Tidepool: Starting up services') the service will already be built and the dependecies located in the `src` directory

### In isolation

If you are building Shoreline in isolation then you need to move a copy of the our [come_deps.sh](https://github.com/tidepool-org/tools/blob/master/come_deps.sh) file into the root of the repository.

Then to get dependencies and build, use:

```
$ source ./build
```

## Running the Tests

### Mock generation

To (re)generate mocks which are used in tests:
```
go generate ./...
```

### All tests

To run all tests for this repo then in the root directory use:

```
$ source gotest
```

### Tests for a specific package

Go into the package directory e.g. `user` then use `go test -v` within that directory.

## Config

### server.json

#### user.clinicDemoUserId (string)

Specify the user ID for the demo account to automatically share with a new signup with VCA.
```
