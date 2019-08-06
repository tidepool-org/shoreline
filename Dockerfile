# Development
FROM golang:1.12.7-alpine AS development

WORKDIR /go/src/github.com/tidepool-org/shoreline

COPY . .

RUN  ./build.sh

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
