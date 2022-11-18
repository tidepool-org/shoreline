# Development
FROM --platform=$BUILDPLATFORM golang:1.17-alpine AS development
ARG APP_VERSION
ARG GOPRIVATE
ARG GITHUB_TOKEN
ENV GO111MODULE=on
WORKDIR /go/src/github.com/mdblp/shoreline
RUN adduser -D tidepool && \
    chown -R tidepool /go/src/github.com/mdblp/shoreline
RUN apk add --no-cache git gcc musl-dev
USER tidepool
COPY --chown=tidepool . .
ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
RUN ./build.sh $TARGETPLATFORM
CMD ["./dist/shoreline"]

# Production
FROM --platform=$BUILDPLATFORM alpine:latest AS production
WORKDIR /home/tidepool
RUN apk --no-cache update && \
    apk --no-cache upgrade && \
    apk add --no-cache ca-certificates && \
    adduser -D tidepool
USER tidepool
COPY --from=development --chown=tidepool /go/src/github.com/mdblp/shoreline/dist/shoreline .
CMD ["./shoreline"]
