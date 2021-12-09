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

LABEL name="SSLCLI Image" \
      vendor="ESSENTIAL KAOS" \
      maintainer="Anton Novojilov" \
      license="Apache-2.0" \
      version="2021.12.10"

COPY --from=builder /go/src/github.com/essentialkaos/sslcli/sslcli /usr/bin/

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates

ENTRYPOINT ["sslcli"]

################################################################################
