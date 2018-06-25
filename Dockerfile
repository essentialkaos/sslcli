FROM golang:alpine

WORKDIR /go/src/github.com/essentialkaos/sslcli
COPY . .

RUN apk add --no-cache make git && \
    make deps && \
    make all

CMD ["sslcli"]
