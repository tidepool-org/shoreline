export TIDEPOOL_KEYCLOAK_CLIENT_ID=shoreline
export TIDEPOOL_KEYCLOAK_CLIENT_SECRET=5cee5afb-77b7-4ae3-938b-595a46a6402e
export TIDEPOOL_KEYCLOAK_BASE_URL=http://localhost:8024
export TIDEPOOL_KEYCLOAK_REALM=dev-local
export TIDEPOOL_KEYCLOAK_ADMIN_USERNAME=admin
export TIDEPOOL_KEYCLOAK_ADMIN_PASSWORD=admin
export TIDEPOOL_KEYCLOAK_MIGRATION_SECRET=test

export TIDEPOOL_STORE_SCHEME="mongodb"
export TIDEPOOL_STORE_ADDRESSES="localhost:27017"
export TIDEPOOL_STORE_DATABASE="user"

export SERVER_SECRET="This needs to be the same secret everywhere. YaHut75NsK1f9UKUXuWqxNN0RUwHFBCy"

export KAFKA_TOPIC="events"
export KAFKA_DEAD_LETTERS_TOPIC="events-shoreline-dl"
export KAFKA_TOPIC_PREFIX="local-"
export KAFKA_VERSION="2.5.1"
export KAFKA_REQUIRE_SSL=false
export KAFKA_BROKERS="localhost:9092"
export CLOUD_EVENTS_SOURCE="shoreline"
export KAFKA_CONSUMER_GROUP="shoreline"

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
