# Development
FROM golang:1.22.2-alpine AS development
WORKDIR /go/src/github.com/tidepool-org/shoreline
RUN adduser -D tidepool && \
    apk add --no-cache git gcc musl-dev && \
    chown -R tidepool /go/src/github.com/tidepool-org/shoreline
USER tidepool
RUN go install github.com/cosmtrek/air@latest
COPY --chown=tidepool . .
RUN ./build.sh
CMD ["air"]

# Production
FROM alpine:latest AS production
WORKDIR /home/tidepool
RUN apk --no-cache update && \
    apk --no-cache upgrade && \
    apk add --no-cache ca-certificates && \
    adduser -D tidepool
USER tidepool
COPY --from=development --chown=tidepool /go/src/github.com/tidepool-org/shoreline/dist/shoreline .
CMD ["./shoreline"]
