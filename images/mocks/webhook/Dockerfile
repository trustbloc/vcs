#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG GO_IMAGE
ARG ALPINE_VER
ARG ALPINE_IMAGE

FROM ${GO_IMAGE}:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . $GOPATH/src/github.com/hyperledger/aries-framework-go
WORKDIR $GOPATH/src/github.com/hyperledger/aries-framework-go
ENV EXECUTABLES go git

FROM golang as aries-framework
ARG GO_TAGS
ARG GOPROXY
RUN GO_TAGS=${GO_TAGS} GOPROXY=${GOPROXY} make sample-webhook


FROM ${ALPINE_IMAGE}:${ALPINE_VER} as base
COPY --from=aries-framework /go/src/github.com/hyperledger/aries-framework-go/build/bin/webhook-server /usr/local/bin
CMD WEBHOOK_PORT=${WEBHOOK_PORT} webhook-server
