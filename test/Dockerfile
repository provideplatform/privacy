FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideplatform
ADD . /go/src/github.com/provideplatform/privacy

RUN mkdir ~/.ssh && cp /go/src/github.com/provideplatform/privacy/ops/keys/ident-id_rsa ~/.ssh/id_rsa && chmod 0600 ~/.ssh/id_rsa && ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
RUN git clone git@github.com:provideplatform/ident.git /go/src/github.com/provideplatform/ident && cd /go/src/github.com/provideplatform/ident
RUN rm -rf ~/.ssh && rm -rf /go/src/github.com/provideplatform/privacy/ops/keys

WORKDIR /go/src/github.com/provideplatform/privacy
RUN make build

ENV TAGS "integration"

ENTRYPOINT ["./ops/run_local_tests.sh"]
