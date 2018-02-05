# Development
FROM golang:1.9.2-alpine AS development

WORKDIR /go/src/github.com/tidepool-org/shoreline

COPY . .

RUN  ./build.sh

CMD ["./dist/shoreline"]

# Release
FROM alpine:latest AS release

RUN ["apk", "add", "--no-cache", "ca-certificates"]

RUN ["adduser", "-D", "tidepool"]

WORKDIR /home/tidepool

USER tidepool

COPY --from=development --chown=tidepool /go/src/github.com/tidepool-org/shoreline/dist/shoreline .

CMD ["./shoreline"]
