# Development
FROM golang:1.9.2-alpine AS development

WORKDIR /go/src/github.com/tidepool-org/shoreline

COPY . .

RUN  ./build.sh

CMD ["./dist/shoreline"]

# Release
FROM alpine:latest AS release

RUN adduser -D shoreline

WORKDIR /home/shoreline

USER shoreline

COPY --from=development --chown=shoreline /go/src/github.com/tidepool-org/shoreline/dist/shoreline .

CMD ["./shoreline"]
