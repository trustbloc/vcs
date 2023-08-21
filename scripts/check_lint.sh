#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.53.3"

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run --timeout 5m
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/profile/reader/file ${GOLANGCI_LINT_IMAGE} golangci-lint run --timeout 5m
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/event ${GOLANGCI_LINT_IMAGE} golangci-lint run --timeout 5m
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/healthchecks ${GOLANGCI_LINT_IMAGE} golangci-lint run --timeout 5m
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/credentialstatus ${GOLANGCI_LINT_IMAGE} golangci-lint run --timeout 5m
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/oidc/fosite ${GOLANGCI_LINT_IMAGE} golangci-lint run --timeout 5m
