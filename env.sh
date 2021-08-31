#!/bin/sh

# Dev env values example

export USER_MAX_FAILED_LOGIN="5"
export USER_DELAY_NEXT_LOGIN="10"
export USER_MAX_CONCURRENT_LOGIN="200"
export USER_BLOCK_CONCURRENT_LOGIN="true"
export USER_TOKEN_DURATION_SECS="3600"
export SERVER_TOKEN_DURATION_SECS="86400"
export LONG_TERM_TOKEN_DURATION_DAYS="30"

export SERVER_SECRET="This needs to be the same secret everywhere. YaHut75NsK1f9UKUXuWqxNN0RUwHFBCy"
export AUTHENT_API_SECRET="This is another secret"
export ZENDESK_SECRET="A third party secret"
export API_SECRET="This is a local API secret for everyone. BsscSHqSHiwrBMJsEGqbvXiuIUPAjQXU"
# Do not use this secret in production!
# Use for testing only, must be empty string in production
export VERIFICATION_SECRET="+skip"
export LONG_TERM_KEY="abcdefghijklmnopqrstuvwxyz"
export SALT="ADihSEI7tOQQP9xfXMO9HfRpXKu1NpIJ"
