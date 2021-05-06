FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/privacy

RUN mkdir ~/.ssh && cp /go/src/github.com/provideapp/privacy/ops/keys/ident-id_rsa ~/.ssh/id_rsa && chmod 0600 ~/.ssh/id_rsa && ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
RUN git clone git@github.com:provideapp/ident.git /go/src/github.com/provideapp/ident && cd /go/src/github.com/provideapp/ident
RUN rm -rf ~/.ssh && rm -rf /go/src/github.com/provideapp/privacy/ops/keys

WORKDIR /go/src/github.com/provideapp/privacy
RUN make build

FROM golang:1.15

RUN mkdir -p /privacy
WORKDIR /privacy

COPY --from=builder /go/src/github.com/provideapp/privacy/.bin /privacy/.bin
COPY --from=builder /go/src/github.com/provideapp/privacy/ops /privacy/ops

ENV TAGS "integration"

ENTRYPOINT ["./ops/run_local_tests.sh"]
