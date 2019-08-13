## BUILDER #####################################################################

FROM golang:alpine as builder

WORKDIR /go/src/github.com/essentialkaos/sslcli

COPY . .

RUN apk add --no-cache git make && \
    make deps && \
    make all

## FINAL IMAGE #################################################################

FROM alpine

LABEL name="SSLCLI Image" \
      vendor="ESSENTIAL KAOS" \
      maintainer="Anton Novojilov" \
      license="EKOL" \
      version="2019.08.14"

COPY --from=builder /go/src/github.com/essentialkaos/sslcli/sslcli /usr/bin/

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["sslcli"]

################################################################################
