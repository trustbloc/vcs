#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG GO_IMAGE
ARG ALPINE_VER

FROM ${GO_IMAGE}:${GO_VER}-alpine${ALPINE_VER} as builder

RUN apk help update && apk add git && apk add ca-certificates
RUN adduser -D -g '' appuser
COPY . $GOPATH/src/github.com/trustbloc/vcs/test/bdd/trustregistry/
WORKDIR $GOPATH/src/github.com/trustbloc/vcs/test/bdd/trustregistry/
ARG GO_PROXY
RUN GOPROXY=${GO_PROXY} CGO_ENABLED=0 go build -o /usr/bin/mock-trustregistry

FROM scratch

LABEL org.opencontainers.image.source https://github.com/trustbloc/vcs/test/bdd/trustregistry

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /usr/bin/mock-trustregistry /usr/bin/mock-trustregistry
USER appuser

ENTRYPOINT ["/usr/bin/mock-trustregistry"]
