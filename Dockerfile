FROM debian:jessie

RUN apt-get update && apt-get install -y curl git

RUN curl -O https://storage.googleapis.com/golang/go1.4.2.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.4.2.linux-amd64.tar.gz

RUN /usr/local/go/bin/go get github.com/tools/godep

EXPOSE 9107

ENV GOPATH /opt/go
RUN /usr/local/go/bin/go get github.com/tools/godep

ADD . /opt/go/src/github.com/tidepool-org/shoreline
WORKDIR /opt/go/src/github.com/tidepool-org/shoreline
RUN /opt/go/bin/godep go install ./...

CMD /opt/go/bin/shoreline
