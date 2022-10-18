# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH=$(abspath .)/.build/bin
VC_REST_PATH=cmd/vc-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS                    ?= ghcr.io
VC_REST_IMAGE_NAME                  ?= trustbloc/vc-server
WEBHOOK_IMAGE_NAME 					?= vcs/sample-webhook
MOCK_VERSION 	?=v1.6.0

# OpenAPI spec
SWAGGER_DOCKER_IMG =quay.io/goswagger/swagger
SWAGGER_VERSION    =v0.29.0
SWAGGER_DIR        ="./test/bdd/fixtures/spec"
SWAGGER_OUTPUT     =$(SWAGGER_DIR)"/openAPI.yml"

# Tool commands (overridable)
ALPINE_VER ?= 3.16
GO_VER ?= 1.19

OS := $(shell uname)
ifeq  ($(OS),$(filter $(OS),Darwin Linux))
	PATH:=$(PATH):$(GOBIN_PATH)
else
	PATH:=$(PATH);$(subst /,\\,$(GOBIN_PATH))
endif

.PHONY: all
all: checks unit-test bdd-test

.PHONY: checks
checks: license lint open-api-spec

.PHONY: generate
generate:
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)
	@GOBIN=$(GOBIN_PATH) go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest
	@go generate ./...

.PHONY: lint
lint: generate
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
vc-rest-docker: generate
	@echo "Building vc rest docker image"
	@docker build -f ./images/vc-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VC_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: sample-webhook
sample-webhook:
	@echo "Building sample webhook server"
	@mkdir -p ./build/bin
	@go build -o ./build/bin/webhook-server test/bdd/webhook/main.go

.PHONY: sample-webhook-docker
sample-webhook-docker:
	@echo "Building sample webhook server docker image"
	@docker build -f ./images/mocks/webhook/Dockerfile --no-cache -t $(WEBHOOK_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: mock-login-consent-docker
mock-login-consent-docker:
	@echo "Building mock login consent server"
	@docker build -f ./images/mocks/loginconsent/Dockerfile --no-cache -t  vcs/mock-login-consent:latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) test/bdd/loginconsent

.PHONY: bdd-test
bdd-test: clean vc-rest-docker sample-webhook-docker mock-login-consent-docker generate-test-keys
	@cd test/bdd && go test -count=1 -v -cover . -p 1 -timeout=10m -race

.PHONY: unit-test
unit-test: generate
	@scripts/check_unit.sh

# TODO (#264): frapsoft/openssl only has an amd64 version. While this does work under amd64 and arm64 Mac OS currently,
#               we should add an arm64 version for systems that can only run arm64 code.
.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --platform linux/amd64 --rm \
		-v $(abspath .):/opt/workspace/vcs \
		--entrypoint /opt/workspace/vcs/scripts/generate_test_keys.sh \
		frapsoft/openssl

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
