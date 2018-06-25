FROM golang:alpine

WORKDIR /go/src/sslcli
COPY . .

RUN make deps
RUN make all

CMD ["sslcli"]
