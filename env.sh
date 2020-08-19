export TIDEPOOL_KEYCLOAK_CLIENT_ID=shoreline
export TIDEPOOL_KEYCLOAK_CLIENT_SECRET=c43e3b70-8bc6-496a-94e4-ed9a18f5c3c0
export TIDEPOOL_KEYCLOAK_BASE_URL=http://localhost:8024
export TIDEPOOL_KEYCLOAK_REALM=todd
export TIDEPOOL_KEYCLOAK_ADMIN_USERNAME=admin
export TIDEPOOL_KEYCLOAK_ADMIN_PASSWORD=admin
export TIDEPOOL_KEYCLOAK_MIGRATION_SECRET=test

export TIDEPOOL_STORE_SCHEME="mongodb"
export TIDEPOOL_STORE_ADDRESSES="localhost:27017"
export TIDEPOOL_STORE_DATABASE="user"

export TIDEPOOL_SHORELINE_ENV='{
    "hakken": { "host": "localhost:8000" },
    "highwater": {
  	    "serviceSpec": { "type": "static", "hosts": ["http://localhost:9191"] },
  	    "name": "highwater",
        "metricsSource" : "user-api-local",
        "metricsVersion" : "v0.0.1"
    },
    "gatekeeper": { "serviceSpec": { "type": "static", "hosts": ["http://localhost:9123"] } }
}'

export TIDEPOOL_SHORELINE_SERVICE='{
    "service": {
        "service": "user-api-local",
        "protocol": "http",
        "host": "localhost:9107",
        "keyFile": "config/key.pem",
        "certFile": "config/cert.pem"
    },
    "mongo": {
        "connectionString": "mongodb://localhost:27017/user"
    },
    "user": {
        "serverSecret": "This needs to be the same secret everywhere. YaHut75NsK1f9UKUXuWqxNN0RUwHFBCy",
        "apiSecret": "This is a local API secret for everyone. BsscSHqSHiwrBMJsEGqbvXiuIUPAjQXU",
        "longTermKey": "abcdefghijklmnopqrstuvwxyz",
        "longTermDaysDuration": 30,
        "tokenDurationSecs": 2592000,
        "salt": "ADihSEI7tOQQP9xfXMO9HfRpXKu1NpIJ",
        "verificationSecret": "+skip",
        "clinicDemoUserId": ""
    },
    "oauth2": {
        "expireDays": 14
    },
    "keycloak": {}
}'
