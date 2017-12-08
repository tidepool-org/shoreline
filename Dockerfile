FROM golang:1.9.1-alpine

# Common ENV
ENV API_SECRET="This is a local API secret for everyone. BsscSHqSHiwrBMJsEGqbvXiuIUPAjQXU" \
    SERVER_SECRET="This needs to be the same secret everywhere. YaHut75NsK1f9UKUXuWqxNN0RUwHFBCy" \
    LONGTERM_KEY="abcdefghijklmnopqrstuvwxyz" \
    DISCOVERY_HOST=hakken:8000 \
    PUBLISH_HOST=hakken \
    METRICS_SERVICE="{ \"type\": \"static\", \"hosts\": [{ \"protocol\": \"http\", \"host\": \"highwater:9191\" }] }" \
    USER_API_SERVICE="{ \"type\": \"static\", \"hosts\": [{ \"protocol\": \"http\", \"host\": \"shoreline:9107\" }] }" \
    SEAGULL_SERVICE="{ \"type\": \"static\", \"hosts\": [{ \"protocol\": \"http\", \"host\": \"seagull:9120\" }] }" \
    GATEKEEPER_SERVICE="{ \"type\": \"static\", \"hosts\": [{ \"protocol\": \"http\", \"host\": \"gatekeeper:9123\" }] }" \
# Container specific ENV
    TIDEPOOL_SHORELINE_ENV="{\"hakken\": { \"host\": \"hakken:8000\"},\"highwater\": {\"serviceSpec\": { \"type\": \"static\", \"hosts\": [\"http://highwater:9191\"]},\"name\": \"highwater\",\"metricsSource\" : \"user-api-local\",\"metricsVersion\" : \"v0.0.1\"},\"gatekeeper\": { \"serviceSpec\": { \"type\": \"static\", \"hosts\": [\"http://gatekeeper:9123\"]}}}" \
    TIDEPOOL_SHORELINE_SERVICE="{\"service\": {\"service\": \"user-api-local\",\"protocol\": \"http\",\"host\": \"localhost:9107\",\"keyFile\": \"config/key.pem\",\"certFile\": \"config/cert.pem\"},\"mongo\": {\"connectionString\": \"mongodb://mongo/user\"},\"user\": {\"serverSecret\": \"This needs to be the same secret everywhere. YaHut75NsK1f9UKUXuWqxNN0RUwHFBCy\",\"apiSecret\": \"This is a local API secret for everyone. BsscSHqSHiwrBMJsEGqbvXiuIUPAjQXU\",\"longTermKey\": \"abcdefghijklmnopqrstuvwxyz\",\"longTermDaysDuration\": 30,\"tokenDurationSecs\": 2592000,\"salt\": \"ADihSEI7tOQQP9xfXMO9HfRpXKu1NpIJ\",\"verificationSecret\": \"+skip\",\"clinicDemoUserId\": \"\"},\"oauth2\": {\"expireDays\": 14}}"
 
WORKDIR /go/src/github.com/tidepool-org/shoreline

COPY . /go/src/github.com/tidepool-org/shoreline

RUN ./build.sh && rm -rf .git .gitignore

CMD ["./dist/shoreline"]
