#!/bin/bash -eu

source env.sh
dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./shoreline
