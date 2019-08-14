## BUILDER #####################################################################

FROM golang:alpine as builder

WORKDIR /go/src/github.com/essentialkaos/sslcli

COPY . .

RUN apk add --no-cache git=~2.22 make=4.2.1-r2 && \
    make deps && \
    make all

## FINAL IMAGE #################################################################

FROM alpine:3.10

LABEL name="SSLCLI Image" \
      vendor="ESSENTIAL KAOS" \
      maintainer="Anton Novojilov" \
      license="EKOL" \
      version="2019.08.14"

COPY --from=builder /go/src/github.com/essentialkaos/sslcli/sslcli /usr/bin/

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates

ENTRYPOINT ["sslcli"]

################################################################################
