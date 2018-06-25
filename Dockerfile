FROM golang:alpine as builder

WORKDIR /go/src/github.com/essentialkaos/sslcli

COPY . .

RUN apk add --no-cache make git && \
    make deps && \
    make all

FROM alpine

COPY --from=builder /go/src/github.com/essentialkaos/sslcli/sslcli /usr/bin/

CMD ["sslcli"]
