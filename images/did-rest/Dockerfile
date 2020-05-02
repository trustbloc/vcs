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
RUN make did-rest


FROM alpine:${ALPINE_VER} as base
COPY --from=edge-service /go/src/github.com/trustbloc/edge-service/.build/bin/did-rest /usr/local/bin
ENTRYPOINT ["did-rest"]
