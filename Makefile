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
OPENAPIGEN_VERSION 					?=v1.11.0
ARIES_FRAMEWORK_VERSION				=	main
MOCK_VERSION 	?=v1.7.0-rc.1
GO_IMAGE 	?=golang
ALPINE_IMAGE 	?=alpine
OPENSSL_IMAGE ?=frapsoft/openssl


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
ALPINE_VER ?= 3.18
GO_ALPINE_VER ?= 3.18
GO_VER ?= 1.21

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
	@GOBIN=$(GOBIN_PATH) go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@$(OPENAPIGEN_VERSION)
	@go generate ./...
	@cd component/credentialstatus && go generate

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
	@docker build -f ./images/vc-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VC_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg GO_ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: vcs-stress
vcs-stress:
	@echo "Building vcs-stress"
	@mkdir -p ./.build/bin
	@echo "Version is '$(VC_REST_VERSION)'"
	@echo "${VCS_STRESS_PATH}"
	@cd ${VCS_STRESS_PATH} && go build -o ../../../.build/bin/vcs-stress

.PHONY: vcs-stress-docker
vcs-stress-docker: generate
	@echo "Building vcs-stress docker image"
	@docker build -f ./images/vcs-stress/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VCS_STRESS_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg GO_ALPINE_VER=$(GO_ALPINE_VER) \
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
	--build-arg ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg GO_IMAGE=$(GO_IMAGE) \
	--build-arg ALPINE_IMAGE=$(ALPINE_IMAGE) .

.PHONY: mock-login-consent-docker
mock-login-consent-docker:
	@echo "Building mock login consent server"
	@docker build -f ./images/mocks/loginconsent/Dockerfile --no-cache -t  vcs/mock-login-consent:latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(GO_ALPINE_VER) \
	--build-arg GO_IMAGE=$(GO_IMAGE) test/bdd/loginconsent

.PHONY: bdd-test
bdd-test: clean vc-rest-docker sample-webhook-docker mock-login-consent-docker generate-test-keys build-krakend-plugin
	@cd test/bdd && go test -count=1 -v -cover . -p 1 -timeout=10m -race

.PHONY: unit-test
unit-test: generate
	@scripts/check_unit.sh

.PHONY: bdd-test-dev
bdd-test-dev: vc-rest-docker
	@cd test/bdd && go test -count=1 -v -cover . -p 1 -timeout=10m -race

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
		ghcr.io/gythialy/golang-cross:1.19.4-0

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
	CREDENTIAL_TEMPLATE_ID= \
	TOKEN_CLIENT_ID= \
	TOKEN_CLIENT_SECRET= \
	CREDENTIAL_TYPE= \
	CLAIM_DATA='' \
	USERS_NUM=3 \
	CONCURRENT_REQ=2 \
	go test -count=1 -v -cover . -p 1 -timeout=10m -race

.PHONY: clean
clean:
	@rm -rf ./.build
	@rm -rf coverage*.out
	@rm -Rf ./test/bdd/docker-compose.log

.PHONY: update-aries
update-aries:
	@find . -type d \( -name build -prune \) -o -name go.mod -print | while read -r gomod_path; do \
		dir_path=$$(dirname "$$gomod_path"); \
		if grep -q "github.com/hyperledger/aries-framework-go" "$$gomod_path"; then \
			echo "Executing 'updating aries' in directory: $$dir_path"; \
			(cd "$$dir_path" && go get github.com/hyperledger/aries-framework-go@$(ARIES_FRAMEWORK_VERSION) && go get github.com/hyperledger/aries-framework-go/component/models@$(ARIES_FRAMEWORK_VERSION) && go mod tidy) || exit 1; \
		fi; \
	done

.PHONY: tidy-modules
tidy-modules:
	@find . -type d \( -name build -prune \) -o -name go.mod -print | while read -r gomod_path; do \
		dir_path=$$(dirname "$$gomod_path"); \
		echo "Executing 'go mod tidy' in directory: $$dir_path"; \
		(cd "$$dir_path" && go mod tidy) || exit 1; \
	done
