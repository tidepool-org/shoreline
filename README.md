shoreline
=========

[![Build Status](https://travis-ci.org/tidepool-org/shoreline.png)](https://travis-ci.org/tidepool-org/shoreline)

Shoreline is the entrance to the ocean; in our case it manages logins and user accounts

## Building

We are doing our own dependancy managment using the Comedeps file. Our `come_deps.sh` is available in the [tools](https://github.com/tidepool-org/tools 'tidepool-org: tools') repository.

To get dependencies and build, use:

```
$ source ./build
```

### Running the Tests

To run the tests locally, the simplest way is to fire up all services with [runservers](http://developer.tidepool.io/starting-up-services/ 'Tidepool: Starting up services') (this is how the dependencies will be fetched), then use `go test -v` within each directory that contains go tests.
