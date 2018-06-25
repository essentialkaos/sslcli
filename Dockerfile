FROM golang:alpine

WORKDIR /go/src/sslcli
COPY . .

RUN apk add --no-cache make git && \
    make deps && \
    make all

CMD ["sslcli"]
