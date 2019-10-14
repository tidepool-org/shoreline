# Development
FROM golang:1.12.7-alpine AS development

RUN apk --no-cache update && \
    apk --no-cache upgrade && \
    apk add build-base git

# Using Go module (go 1.12 need this variable to be set to enable modules)
# The variable should default to "on", in Go 1.14 release
ENV GO111MODULE on

WORKDIR /go/src/github.com/tidepool-org/shoreline
COPY . .
RUN go get
RUN ./build.sh

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
