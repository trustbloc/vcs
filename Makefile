# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

VC_REST_PATH=cmd/vc-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= docker.pkg.github.com
VC_REST_IMAGE_NAME   ?= trustbloc/edge-service/vc-rest

# Tool commands (overridable)
ALPINE_VER ?= 3.10
GO_VER ?= 1.13.1

.PHONY: all
all: checks unit-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: vc-rest
vc-rest:
	@echo "Building vc-rest"
	@mkdir -p ./build/bin
	@cd ${VC_REST_PATH} && go build -o ../../build/bin/vc-rest main.go

.PHONY: vc-rest-docker
vc-rest-docker:
	@echo "Building vc rest docker image"
	@docker build -f ./images/vc-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VC_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

unit-test:
	@scripts/check_unit.sh
