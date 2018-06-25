FROM golang:alpine

WORKDIR /go/src/sslcli
COPY . .

RUN apk add --no-cache make && \
    make deps && \
    make all

CMD ["sslcli"]
