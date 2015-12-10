FROM debian:jessie

RUN apt-get update && apt-get install -y curl git

RUN curl -O https://storage.googleapis.com/golang/go1.4.2.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.4.2.linux-amd64.tar.gz

ENV GOROOT /usr/local/go
ENV GOPATH /opt/go
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH

RUN go get github.com/tools/godep

ADD . /opt/go/src/github.com/tidepool-org/shoreline
WORKDIR /opt/go/src/github.com/tidepool-org/shoreline
RUN godep go install ./...

EXPOSE 9107

CMD shoreline
