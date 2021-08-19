FROM golang:1.16 AS builder

RUN mkdir -p /go/src/github.com/provideplatform
ADD . /go/src/github.com/provideplatform/privacy

WORKDIR /go/src/github.com/provideplatform/privacy
RUN make build

FROM alpine

RUN apk add --no-cache bash libc6-compat

RUN mkdir -p /privacy
WORKDIR /privacy

COPY --from=builder /go/src/github.com/provideplatform/privacy/.bin /privacy/.bin
COPY --from=builder /go/src/github.com/provideplatform/privacy/ops /privacy/ops

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
