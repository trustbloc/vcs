#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . src/github.com/trustbloc/edge-service
WORKDIR src/github.com/trustbloc/edge-service
ENV EXECUTABLES go git

FROM golang as edge-service
RUN make comparator-rest


FROM alpine:${ALPINE_VER} as base
LABEL org.opencontainers.image.source https://github.com/trustbloc/edge-service

COPY --from=edge-service /go/src/github.com/trustbloc/edge-service/.build/bin/comparator-rest /usr/local/bin

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

ENTRYPOINT ["comparator-rest"]
