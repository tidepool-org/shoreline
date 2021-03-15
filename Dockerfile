# Development
FROM golang:1.15-alpine AS development

ENV GO111MODULE on
WORKDIR /go/src/github.com/mdblp/shoreline
RUN adduser -D tidepool && \
    chown -R tidepool /go/src/github.com/mdblp/shoreline
RUN apk add --no-cache git
USER tidepool
COPY --chown=tidepool . .
RUN ./build.sh
CMD ["./dist/shoreline"]

# Production
FROM alpine:latest AS production
WORKDIR /home/tidepool
RUN apk --no-cache update && \
    apk --no-cache upgrade && \
    apk add --no-cache ca-certificates && \
    adduser -D tidepool
USER tidepool
COPY --from=development --chown=tidepool /go/src/github.com/mdblp/shoreline/dist/shoreline .
CMD ["./shoreline"]
