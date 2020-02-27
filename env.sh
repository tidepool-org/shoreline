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
        "connectionString": "mongodb://localhost/user"
    },
    "user": {
        "secrets": [{\"secret\": \"default\", \"pass\": \"xxxxxxxxx\"}, {\"secret\": \"product_website\", \"pass\": \"xxxxxxxxx\"}],
        "apiSecret": "This is a local API secret for everyone. BsscSHqSHiwrBMJsEGqbvXiuIUPAjQXU",
        "longTermKey": "abcdefghijklmnopqrstuvwxyz",
        "longTermDaysDuration": 30,
        "tokenDurationSecs": 2592000,
        "salt": "ADihSEI7tOQQP9xfXMO9HfRpXKu1NpIJ",
        "maxFailedLogin": 5,
        "delayBeforeNextLoginAttempt": 10,
        "maxConcurrentLogin": 100,
        "verificationSecret": "+skip",
        "clinicDemoUserId": ""
    },
    "oauth2": {
        "expireDays": 14
    }
}'
