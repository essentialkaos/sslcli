## BUILDER #####################################################################

FROM golang:alpine as builder

WORKDIR /go/src/github.com/essentialkaos/sslcli

COPY . .

ENV GO111MODULE=auto

# hadolint ignore=DL3018
RUN apk add --no-cache git make upx && \
    make deps && \
    make all && \
    upx sslcli

## FINAL IMAGE #################################################################

FROM essentialkaos/alpine:3.13

LABEL org.opencontainers.image.title="sslcli" \
      org.opencontainers.image.description="Pretty awesome command-line client for public SSLLabs API" \
      org.opencontainers.image.vendor="ESSENTIAL KAOS" \
      org.opencontainers.image.authors="Anton Novojilov" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://kaos.sh/sslcli" \
      org.opencontainers.image.source="https://github.com/essentialkaos/sslcli"

COPY --from=builder /go/src/github.com/essentialkaos/sslcli/sslcli /usr/bin/

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates

ENTRYPOINT ["sslcli"]

################################################################################
