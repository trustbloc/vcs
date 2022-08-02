# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

VC_REST_PATH=cmd/vc-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS                    ?= ghcr.io
VC_REST_IMAGE_NAME                  ?= trustbloc/vc-server
DID_ELEMENT_SIDETREE_REQUEST_URL    ?= https://element-did.com/api/v1/sidetree/requests

# OpenAPI spec
SWAGGER_DOCKER_IMG =quay.io/goswagger/swagger
SWAGGER_VERSION    =v0.29.0
SWAGGER_DIR        ="./test/bdd/fixtures/spec"
SWAGGER_OUTPUT     =$(SWAGGER_DIR)"/openAPI.yml"

# Tool commands (overridable)
ALPINE_VER ?= 3.14
GO_VER ?= 1.18

GOBIN_PATH=$(abspath .)/.build/bin

.PHONY: all
all: checks unit-test bdd-test

.PHONY: checks
checks: license lint open-api-spec

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: vc-rest
vc-rest:
	@echo "Building vc-rest"
	@mkdir -p ./.build/bin
	@cd ${VC_REST_PATH} && go build -o ../../.build/bin/vc-rest main.go

.PHONY: vc-rest-docker
vc-rest-docker:
	@echo "Building vc rest docker image"
	@docker build -f ./images/vc-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VC_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: bdd-test
bdd-test: clean vc-rest-docker generate-test-keys
	@cd test/bdd && go test -count=1 -v -cover . -p 1 -timeout=10m -race

.PHONY: bdd-interop-test
bdd-interop-test:clean vc-rest-docker generate-test-keys
	@scripts/check_integration_interop.sh

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/vcs \
		--entrypoint "/opt/workspace/vcs/scripts/generate_test_keys.sh" \
		frapsoft/openssl

create-element-did: clean
	@mkdir -p .build
	@cp scripts/create-element-did.js .build/
	@REQUEST_URL=$(DID_ELEMENT_SIDETREE_REQUEST_URL) scripts/create_element_did.sh

# this target creates VCs and VPs from other systems for interop tests
prepare-test-verifiables: clean
	@mkdir -p .build
	@cp scripts/prepare-test-verifiables.js .build/
	@scripts/prepare_test_verifiables.sh

.PHONY: open-api-spec
open-api-spec: clean
	@GOBIN=$(GOBIN_PATH) go install github.com/go-swagger/go-swagger/cmd/swagger@$(SWAGGER_VERSION)
	@echo "Generating Open API spec"
	@mkdir $(SWAGGER_DIR)
	@$(GOBIN_PATH)/swagger generate spec -w ./cmd/vc-rest -x github.com/trustbloc/orb -o $(SWAGGER_OUTPUT)
	@echo "Validating generated spec"
	@$(GOBIN_PATH)/swagger validate $(SWAGGER_OUTPUT)

.PHONY: open-api-demo
open-api-demo: clean open-api-spec generate-test-keys vc-rest-docker
	@echo "Running Open API demo on http://localhost:8089/openapi"
	@docker-compose -f test/bdd/fixtures/docker-compose.yml up --force-recreate -d vc-openapi.trustbloc.local

.PHONY: clean
clean:
	@rm -rf ./build
	@rm -rf coverage*.out
	@rm -Rf ./test/bdd/docker-compose.log
	@rm -rf $(SWAGGER_DIR)
