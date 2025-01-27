# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH=$(abspath .)/.build/bin
VC_REST_PATH=cmd/vc-rest
VCS_STRESS_PATH=test/stress/cmd
# Namespace for the agent images
DOCKER_OUTPUT_NS                    ?= ghcr.io
VC_REST_IMAGE_NAME                  ?= trustbloc/vc-server
VCS_STRESS_IMAGE_NAME				?= trustbloc/vcs-stress
WEBHOOK_IMAGE_NAME 					?= vcs/sample-webhook
COGNITO_AUTH_IMAGE_NAME				?= vcs/sample-cognito-auth
OPENAPIGEN_VERSION 					?=v2.4.1
MOCK_VERSION 	?=v1.7.0-rc.1
GO_IMAGE 	?=golang
ALPINE_IMAGE 	?=alpine
OPENSSL_IMAGE ?=frapsoft/openssl
GOPROXY ?= https://proxy.golang.org

VC_FRAMEWORK_VERSION				= c11d6ee3d4124c590a2b0f23279f12e2e9fbae20
KMS_FRAMEWORK_VERSION 				= v1.2.1
DID_GO_VERSION						= v1.3.2
SIDE_TREE_VERSION					= f4260aff710479ba5fa3f0c61b51d451d9041225

BUILD_DATE=$(shell date +'%Y%m%d%H%M%S' -d @$(shell git show -s --format=%ct))
VC_REST_VERSION ?= $(subst v,,"$(shell git name-rev --tags --name-only $(shell git rev-parse HEAD))+$(BUILD_DATE)")
ifneq (,$(findstring undefined,"$(VC_REST_VERSION)"))
	TAG=$(shell git describe --tags --abbrev=0)
	RCPREFIX="-RC1"
	ifneq (,$(findstring -rc,"$(TAG)"))
		RCPREFIX=""
	endif
	VC_REST_VERSION = $(subst v,,"$(TAG)$(RCPREFIX)+$(BUILD_DATE)-$(shell git rev-parse --short HEAD)")
endif

# Tool commands (overridable)
ALPINE_VER ?= 3.21
GO_ALPINE_VER ?= 3.21
GO_VER ?= 1.23

OS := $(shell uname)
ifeq  ($(OS),$(filter $(OS),Darwin Linux))
	PATH:=$(PATH):$(GOBIN_PATH)
else
	PATH:=$(PATH);$(subst /,\\,$(GOBIN_PATH))
endif

.PHONY: all
all: checks unit-test bdd-test

.PHONY: checks
checks: license lint

.PHONY: generate
generate:
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)
	@GOBIN=$(GOBIN_PATH) go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OPENAPIGEN_VERSION)
	@go generate ./...
	@cd component/credentialstatus && go generate
	@cd component/oidc/fosite && go generate ./...

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
	@echo "Version is '$(VC_REST_VERSION)'"
	@cd ${VC_REST_PATH} && go build -ldflags="-X main.Version=$(VC_REST_VERSION)" -o ../../.build/bin/vc-rest main.go

.PHONY: vc-rest-docker
vc-rest-docker: generate
	@echo "Building vc rest docker image"
	@docker build -f ./images/vc-rest/Dockerfile -t $(DOCKER_OUTPUT_NS)/$(VC_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg GO_PROXY=$(GOPROXY) \
	--build-arg GO_ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: vcs-stress
vcs-stress:
	@echo "Building vcs-stress"
	@mkdir -p ./.build/bin
	@echo "Version is '$(VC_REST_VERSION)'"
	@echo "${VCS_STRESS_PATH}"
	@cd ${VCS_STRESS_PATH} && GOPROXY=$(GOPROXY) go build -o ../../../.build/bin/vcs-stress

.PHONY: vcs-stress-docker
vcs-stress-docker: generate
	@echo "Building vcs-stress docker image"
	@docker build -f ./images/vcs-stress/Dockerfile -t $(DOCKER_OUTPUT_NS)/$(VCS_STRESS_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg GO_PROXY=$(GOPROXY) \
	--build-arg GO_ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .


.PHONY: sample-webhook
sample-webhook:
	@echo "Building sample webhook server"
	@mkdir -p ./build/bin
	@go build -modfile test/bdd/go.mod -o ./build/bin/webhook-server test/bdd/webhook/main.go

.PHONY: sample-webhook-docker
sample-webhook-docker:
	@echo "Building sample webhook server docker image"
	@docker build -f ./images/mocks/webhook/Dockerfile -t $(WEBHOOK_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg GO_PROXY=$(GOPROXY) \
	--build-arg GO_IMAGE=$(GO_IMAGE) \
	--build-arg ALPINE_IMAGE=$(ALPINE_IMAGE) .

.PHONY: mock-login-consent-docker
mock-login-consent-docker:
	@echo "Building mock login consent server"
	@docker build -f ./images/mocks/loginconsent/Dockerfile -t  vcs/mock-login-consent:latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg GO_PROXY=$(GOPROXY) \
	--build-arg GO_IMAGE=$(GO_IMAGE) test/bdd/loginconsent

.PHONY: mock-trustregistry-docker
mock-trustregistry-docker:
	@echo "Building mock Trust Registry server"
	@docker build -f ./images/mocks/trustregistry/Dockerfile -t  vcs/mock-trustregistry:latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg GO_PROXY=$(GOPROXY) \
	--build-arg GO_IMAGE=$(GO_IMAGE) test/bdd/trustregistry

.PHONY: mock-attestation-docker
mock-attestation-docker:
	@echo "Building mock attestation server"
	@docker build -f ./images/mocks/attestation/Dockerfile --no-cache -t  vcs/mock-attestation:latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg GO_PROXY=$(GOPROXY) \
	--build-arg GO_IMAGE=$(GO_IMAGE) test/bdd/attestation

.PHONY: sample-cognito-auth
sample-cognito-auth:
	@echo "Building sample cognito auth server"
	@mkdir -p ./build/bin
	@GOPROXY=$(GOPROXY) go build -C test/bdd/cognito-auth -modfile ../../../test/bdd/go.mod -o ./../../../build/bin/cognito-auth-server

.PHONY: sample-cognito-auth-docker
sample-cognito-auth-docker:
	@echo "Building sample cognito-auth server docker image"
	@docker build -f ./images/mocks/cognito-auth/Dockerfile --no-cache -t $(COGNITO_AUTH_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg GO_IMAGE=$(GO_IMAGE) \
	--build-arg GO_PROXY=$(GOPROXY) \
	--build-arg ALPINE_IMAGE=$(ALPINE_IMAGE) .


.PHONY: bdd-test
bdd-test: clean vc-rest-docker sample-cognito-auth-docker sample-webhook-docker mock-login-consent-docker mock-trustregistry-docker mock-attestation-docker generate-test-keys build-krakend-plugin
	@cd test/bdd && GOPROXY=$(GOPROXY) go test -count=1 -v -cover . -p 1 -timeout=10m -race

.PHONY: unit-test
unit-test: generate
	@scripts/check_unit.sh

.PHONY: bdd-test-dev
bdd-test-dev: vc-rest-docker
	@cd test/bdd && GOPROXY=$(GOPROXY) go test -count=1 -v -cover . -p 1 -timeout=10m -race

# TODO (#264): frapsoft/openssl only has an amd64 version. While this does work under amd64 and arm64 Mac OS currently,
#               we should add an arm64 version for systems that can only run arm64 code.
.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --platform linux/amd64 --rm \
		-v $(abspath .):/opt/workspace/vcs \
		--entrypoint /opt/workspace/vcs/scripts/generate_test_keys.sh \
		$(OPENSSL_IMAGE)

.PHONY: build-wallet-cli-binaries
build-wallet-cli-binaries: clean
	@mkdir -p .build/dist/bin
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/vcs \
		--entrypoint "/opt/workspace/vcs/scripts/build-cli.sh" \
		ghcr.io/gythialy/golang-cross:1.22.4-0

.PHONY: build-krakend-plugin
build-krakend-plugin: clean
	@docker run -i --platform linux/amd64 --rm \
		-v $(abspath .):/opt/workspace/vcs \
		-w /opt/workspace/vcs/test/bdd/krakend-plugins/http-client-no-redirect \
		devopsfaith/krakend-plugin-builder:2.1.3 \
		go build -buildmode=plugin -o /opt/workspace/vcs/test/bdd/fixtures/krakend-config/plugins/http-client-no-redirect.so .

.PHONY: stress-test
stress-test:
	@cd test/bdd && \
	TAGS=oidc4vc_stress \
	DISABLE_COMPOSITION=true \
	VCS_API_URL= \
	ISSUER_PROFILE_ID= \
	VERIFIER_PROFILE_ID= \
	VERIFIER_PROFILE_VERSION= \
	VERIFIER_PRESENTATION_ID= \
	CREDENTIAL_TEMPLATE_ID= \
	TOKEN_CLIENT_ID= \
	TOKEN_CLIENT_SECRET= \
	CREDENTIAL_TYPE= \
	CLAIM_DATA='' \
	USERS_NUM=3 \
	CONCURRENT_REQ=2 \
	GOPROXY=$(GOPROXY) go test -count=1 -v -cover . -p 1 -timeout=10m -race

.PHONY: clean
clean:
	@rm -rf ./.build
	@rm -rf coverage*.out
	@rm -Rf ./test/bdd/docker-compose.log

.PHONY: update-vc
update-vc:
	@find . -type d \( -name build -prune \) -o -name go.mod -print | while read -r gomod_path; do \
		dir_path=$$(dirname "$$gomod_path"); \
		if grep -q "github.com/trustbloc/vc-go" "$$gomod_path"; then \
			echo "Executing 'updating vc' in directory: $$dir_path"; \
			(cd "$$dir_path" && GOPROXY=$(GOPROXY) go get github.com/trustbloc/vc-go@$(VC_FRAMEWORK_VERSION) && go mod tidy) || exit 1; \
		fi; \
	done

.PHONY: update-kms
update-kms:
	@find . -type d \( -name build -prune \) -o -name go.mod -print | while read -r gomod_path; do \
		dir_path=$$(dirname "$$gomod_path"); \
		if grep -q "github.com/trustbloc/kms-go" "$$gomod_path"; then \
			echo "Executing 'updating vc' in directory: $$dir_path"; \
			(cd "$$dir_path" && GOPROXY=$(GOPROXY) go get github.com/trustbloc/kms-go@$(KMS_FRAMEWORK_VERSION) && go mod tidy) || exit 1; \
		fi; \
	done

.PHONY: update-did
update-did:
	@find . -type d \( -name build -prune \) -o -name go.mod -print | while read -r gomod_path; do \
		dir_path=$$(dirname "$$gomod_path"); \
		if grep -q "github.com/trustbloc/did-go" "$$gomod_path"; then \
			echo "Executing 'updating vc' in directory: $$dir_path"; \
			(cd "$$dir_path" && GOPROXY=$(GOPROXY) go get github.com/trustbloc/did-go@$(DID_GO_VERSION) && go mod tidy) || exit 1; \
		fi; \
	done

.PHONY: update-sidetree
update-sidetree:
	@find . -type d \( -name build -prune \) -o -name go.mod -print | while read -r gomod_path; do \
		dir_path=$$(dirname "$$gomod_path"); \
		if grep -q "github.com/trustbloc/sidetree-go" "$$gomod_path"; then \
			echo "Executing 'updating vc' in directory: $$dir_path"; \
			(cd "$$dir_path" && GOPROXY=$(GOPROXY) go get github.com/trustbloc/sidetree-go@$(SIDE_TREE_VERSION) && go mod tidy) || exit 1; \
		fi; \
	done

.PHONY: tidy-modules
tidy-modules:
	@find . -type d \( -name build -prune \) -o -name go.mod -print | while read -r gomod_path; do \
		dir_path=$$(dirname "$$gomod_path"); \
		echo "Executing 'go mod tidy' in directory: $$dir_path"; \
		(cd "$$dir_path" && GOPROXY=$(GOPROXY) go mod tidy) || exit 1; \
	done
