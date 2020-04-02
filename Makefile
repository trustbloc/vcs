# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

VC_REST_PATH=cmd/vc-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= docker.pkg.github.com
VC_REST_IMAGE_NAME   ?= trustbloc/edge-service/vc-rest
DID_ELEMENT_SIDETREE_REQUEST_URL ?= https://element-did.com/api/v1/sidetree/requests
# LOCAL UNIVERSAL REGISTRAR ENDPOINT
UNIVERSAL_REGISTRAR_LOCAL ?= http://localhost:9080
# REMOTE UNIVERSAL REGISTRAR ENDPOINT
UNIVERSAL_REGISTRAR_REMOTE ?= https://uniregistrar.io

# Tool commands (overridable)
ALPINE_VER ?= 3.10
GO_VER ?= 1.13.1

.PHONY: all
all: checks unit-test bdd-test

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
	@mkdir -p ./.build/bin
	@cd ${VC_REST_PATH} && go build -o ../../.build/bin/vc-rest main.go

.PHONY: vc-rest-docker
vc-rest-docker:
	@echo "Building vc rest docker image"
	@docker build -f ./images/vc-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VC_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: bdd-test
bdd-test: clean generate-test-config vc-rest-docker generate-test-keys
	@scripts/check_integration.sh

unit-test:
	@scripts/check_unit.sh

.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/edge-service \
		--entrypoint "/opt/workspace/edge-service/scripts/generate_test_keys.sh" \
		frapsoft/openssl


.PHONY: generate-test-config
generate-test-config:
	@scripts/generate_test_config.sh

create-element-did: clean
	@mkdir -p .build
	@cp scripts/create-element-did.js .build/
	@REQUEST_URL=$(DID_ELEMENT_SIDETREE_REQUEST_URL) scripts/create_element_did.sh

uniregistrar-create-dids: clean
	@mkdir -p .build
	@cp scripts/uniregistrar-create-dids.js .build/
	@UNIREGISTRAR_LOCAL=$(UNIVERSAL_REGISTRAR_LOCAL) UNIREGISTRAR_REMOTE=$(UNIVERSAL_REGISTRAR_REMOTE) scripts/uniregistrar_create_dids.sh

# this target creates VCs and VPs from other systems for interop tests
prepare-test-verifiables: clean
	@mkdir -p .build
	@cp scripts/prepare-test-verifiables.js .build/
	@scripts/prepare_test_verifiables.sh

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./test/bdd/fixtures/keys/tls
	@rm -Rf ./test/bdd/docker-compose.log
	@rm -Rf ./test/bdd/fixtures/discovery-server/config
	@rm -Rf ./test/bdd/fixtures/stakeholder-server/config
