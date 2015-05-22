shoreline
=========

[![Build Status](https://travis-ci.org/tidepool-org/shoreline.png)](https://travis-ci.org/tidepool-org/shoreline)

Shoreline is the entrance to the ocean; in our case it manages logins and user accounts

## Building

We are doing our own dependancy managment using the Comedeps file. To build as expected then run the command below

```
$ source ./build
```

### Running the Tests

To run the tests locally, the simplest way is to fire up all services with [runservers](http://developer.tidepool.io/starting-up-services/ 'Tidepool: Starting up services') (this is how the dependencies will be fetched), then use `go test -v` within each directory that contains go tests.
