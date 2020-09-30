# Development
FROM golang:1.14.7-alpine AS development
WORKDIR /go/src/github.com/tidepool-org/shoreline
RUN adduser -D tidepool && \
    apk add --no-cache git gcc musl-dev && \
    chown -R tidepool /go/src/github.com/tidepool-org/shoreline
ADD https://www.amazontrust.com/repository/SFSRootCAG2.pem /usr/local/share/ca-certificates
RUN update-ca-certificates
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
ADD https://www.amazontrust.com/repository/SFSRootCAG2.pem /usr/local/share/ca-certificates
RUN update-ca-certificates
USER tidepool
COPY --from=development --chown=tidepool /go/src/github.com/tidepool-org/shoreline/dist/shoreline .
CMD ["./shoreline"]
