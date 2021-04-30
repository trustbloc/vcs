# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

VC_REST_PATH=cmd/vc-rest
DID_REST_PATH=cmd/did-rest
VAULT_REST_PATH=cmd/vault-server
COMPARATOR_REST_PATH=cmd/comparator-rest
CONFIDENTIAL_STORAGE_HUB_PATH=cmd/confidential-storage-hub

# Namespace for the agent images
DOCKER_OUTPUT_NS                    ?= ghcr.io
VC_REST_IMAGE_NAME                  ?= trustbloc/vc-server
COMPARATOR_REST_IMAGE_NAME          ?= trustbloc/comparator-server
CONFIDENTIAL_STORAGE_HUB_IMAGE_NAME ?= trustbloc/hub-confidential-storage
VAULT_SERVER_IMAGE_NAME				?= trustbloc/vault-server
DID_REST_IMAGE_NAME                 ?= trustbloc/did-resolver
DID_ELEMENT_SIDETREE_REQUEST_URL    ?= https://element-did.com/api/v1/sidetree/requests

# OpenAPI spec
OPENAPI_DOCKER_IMG=quay.io/goswagger/swagger
OPENAPI_SPEC_PATH=.build/rest/openapi/spec
OPENAPI_DOCKER_IMG_VERSION=v0.26.0

# Tool commands (overridable)
ALPINE_VER ?= 3.12
GO_VER ?= 1.16

.PHONY: all
all: checks unit-test bdd-test

.PHONY: checks
checks: license lint check-openapi-specs

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


.PHONY: comparator-rest
comparator-rest:
	@echo "Building comparator-rest"
	@mkdir -p ./.build/bin
	@cd ${COMPARATOR_REST_PATH} && go build -o ../../.build/bin/comparator-rest main.go

.PHONY: vault-server
vault-server:
	@echo "Building vault-server"
	@mkdir -p ./.build/bin
	@cd ${VAULT_REST_PATH} && go build -o ../../.build/bin/vault-server main.go

.PHONY: confidential-storage-hub
confidential-storage-hub:
	@echo "Building confidential-storage-hub"
	@mkdir -p .build/bin
	@cd ${CONFIDENTIAL_STORAGE_HUB_PATH} && go build -o ../../.build/bin/confidential-storage-hub main.go

.PHONY: confidential-storage-hub-docker
confidential-storage-hub-docker:
	@echo "Building confidential-storage-hub docker image"
	@docker build -f ./images/confidential-storage-hub/Dockerfile --no-cache -t ${DOCKER_OUTPUT_NS}/${CONFIDENTIAL_STORAGE_HUB_IMAGE_NAME}:latest \
		--build-arg GO_VER=${GO_VER} \
		--build-arg ALPINE_VER=${ALPINE_VER} .

.PHONY: vault-server-docker
vault-server-docker:
	@echo "Building vault-server docker image"
	@docker build -f ./images/vault-server/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VAULT_SERVER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: vc-server-docker
vc-server-docker:
	@echo "Building vc rest docker image"
	@docker build -f ./images/vc-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VC_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .


.PHONY: comparator-rest-docker
comparator-rest-docker:
	@echo "Building comparator rest docker image"
	@docker build -f ./images/comparator-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(COMPARATOR_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: did-rest
did-rest:
	@echo "Building did-rest"
	@mkdir -p ./.build/bin
	@cd ${DID_REST_PATH} && go build -o ../../.build/bin/did-rest main.go

.PHONY: did-resolver-docker
did-resolver-docker:
	@echo "Building did rest docker image"
	@docker build -f ./images/did-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(DID_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: docker
docker: vc-server-docker did-resolver-docker comparator-rest-docker confidential-storage-hub-docker vault-server-docker

.PHONY: bdd-test
bdd-test: clean docker generate-test-keys
	@scripts/check_integration.sh

.PHONY: bdd-interop-test
bdd-interop-test:clean vc-server-docker did-resolver-docker comparator-rest-docker confidential-storage-hub-docker vault-server-docker generate-test-keys
	@scripts/check_integration_interop.sh

unit-test:
	@scripts/check_unit.sh

.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/edge-service \
		--entrypoint "/opt/workspace/edge-service/scripts/generate_test_keys.sh" \
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

.PHONY: check-openapi-specs
check-openapi-specs: generate-openapi-spec generate-openapi-spec-vault generate-openapi-spec-confidential-storage-hub generate-openapi-spec-comparator

.PHONY: generate-openapi-spec
generate-openapi-spec: clean
	@echo "Generating and validating controller API specifications using Open API"
	@mkdir -p ${OPENAPI_SPEC_PATH}
	@SPEC_META=$(VC_REST_PATH) SPEC_LOC=${OPENAPI_SPEC_PATH}  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh

.PHONY: generate-openapi-spec-vault
generate-openapi-spec-vault: clean
	@echo "Generating and validating controller API specifications using Open API"
	@mkdir -p ${OPENAPI_SPEC_PATH}/vault
	@SPEC_META=$(VAULT_REST_PATH) SPEC_LOC=${OPENAPI_SPEC_PATH}/vault  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh

.PHONY: generate-openapi-spec-confidential-storage-hub
generate-openapi-spec-confidential-storage-hub: clean
	@echo "Generating and validating confidential-storage-hub API OpenAPI specifications"
	@mkdir -p ${OPENAPI_SPEC_PATH}/confidential-storage-hub
	@SPEC_META=$(CONFIDENTIAL_STORAGE_HUB_PATH) SPEC_LOC=${OPENAPI_SPEC_PATH}/confidential-storage-hub  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh


.PHONY: generate-openapi-spec-comparator
generate-openapi-spec-comparator: clean
	@echo "Generating and validating comparator API OpenAPI specifications"
	@mkdir -p ${OPENAPI_SPEC_PATH}/comparator
	@SPEC_META=$(COMPARATOR_REST_PATH) SPEC_LOC=${OPENAPI_SPEC_PATH}/comparator  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh


.PHONY: generate-models-client-comparator
generate-models-client-comparator:
	@echo "Generating comparator models and client"
	@MODELS_PATH=pkg/restapi/comparator/operation CLIENT_PATH=pkg/client/comparator SPEC_LOC=${COMPARATOR_REST_PATH}/docs/openapi.yaml  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-models-client.sh


.PHONY: generate-openapi-demo-specs
generate-openapi-demo-specs: clean generate-openapi-spec vc-server-docker did-resolver-docker
	@echo "Generate demo agent rest controller API specifications using Open API"
	@SPEC_PATH=${OPENAPI_SPEC_PATH} OPENAPI_DEMO_PATH=test/bdd/fixtures/openapi-demo \
    	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
    	scripts/generate-openapi-demo-specs.sh

.PHONY: run-openapi-demo
run-openapi-demo: generate-test-keys  generate-openapi-demo-specs
	@echo "Starting demo vc rest containers ..."
	@FIXTURES_PATH=test/bdd/fixtures  \
        scripts/run-openapi-demo.sh

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./test/bdd/fixtures/keys/tls
	@rm -Rf ./test/bdd/docker-compose.log
	@rm -Rf ./test/bdd/fixtures/wellknown/jws
	@rm -Rf ./test/bdd/fixtures/discovery-server/config
	@rm -Rf ./test/bdd/fixtures/stakeholder-server/config
