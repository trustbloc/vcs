#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v2.5.0"

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

lint_tasks=(
    "."
    "component/profile/reader/file"
    "component/event"
    "component/healthchecks"
    "component/credentialstatus"
    "component/oidc/fosite"
)

run_lint() {
    local task_dir=$1
    ${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} \
        -v $(pwd):/opt/workspace \
        -w /opt/workspace/$task_dir ${GOLANGCI_LINT_IMAGE} \
        golangci-lint run --timeout 5m --tests=false
}

if [ "$LINT_CONCURRENTLY" = "true" ]; then
    for task in "${lint_tasks[@]}"; do
        run_lint "$task" &
    done
    wait
else
    for task in "${lint_tasks[@]}"; do
        run_lint "$task"
    done
fi
