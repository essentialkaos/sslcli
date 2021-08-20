## BUILDER #####################################################################

FROM golang:alpine as builder

WORKDIR /go/src/github.com/essentialkaos/sslcli

COPY . .

ENV GO111MODULE=auto

RUN apk add --no-cache git=~2.32 make=4.3-r0 upx=3.96-r1 && \
    make deps && \
    make all && \
    upx sslcli

## FINAL IMAGE #################################################################

FROM essentialkaos/alpine:3.13

LABEL name="SSLCLI Image" \
      vendor="ESSENTIAL KAOS" \
      maintainer="Anton Novojilov" \
      license="EKOL" \
      version="2021.08.21"

COPY --from=builder /go/src/github.com/essentialkaos/sslcli/sslcli /usr/bin/

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates

ENTRYPOINT ["sslcli"]

################################################################################
