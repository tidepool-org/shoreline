# Development
FROM golang:1.11.4-alpine AS development

WORKDIR /go/src/github.com/tidepool-org/shoreline

COPY . .

RUN apk --no-cache update && \
    apk --no-cache upgrade && \
    apk add build-base git

RUN go get -u github.com/golang/dep/cmd/dep

RUN dos2unix build.sh && \
    dos2unix test.sh && \
    ./build.sh

CMD ["./dist/shoreline"]

# Release
FROM alpine:latest AS release

RUN apk --no-cache update && \
    apk --no-cache upgrade && \
    apk add --no-cache ca-certificates && \
    adduser -D tidepool

WORKDIR /home/tidepool

USER tidepool

COPY --from=development --chown=tidepool /go/src/github.com/tidepool-org/shoreline/dist/shoreline .

CMD ["./shoreline"]
