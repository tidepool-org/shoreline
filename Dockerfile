# Development
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS development
ARG APP_VERSION
ARG GOPRIVATE
ARG GITHUB_TOKEN
ENV GO111MODULE=on
WORKDIR /go/src/github.com/mdblp/shoreline
RUN adduser -D tidepool && \
    chown -R tidepool /go/src/github.com/mdblp/shoreline
RUN apk add --no-cache git
USER tidepool
COPY --chown=tidepool . .
ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
RUN ./build.sh $TARGETPLATFORM
CMD ["./dist/shoreline"]

# Production
FROM gcr.io/distroless/static:nonroot AS production
WORKDIR /home/mdblp
USER nonroot
COPY --from=development --chown=nonroot /go/src/github.com/mdblp/shoreline/dist/shoreline .
CMD ["./shoreline"]
