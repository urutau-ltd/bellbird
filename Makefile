SHELL := /bin/sh

GO ?= go
CGO_ENABLED ?= 0
RACE_CGO_ENABLED ?= 1
GOCACHE := /tmp/go-build

BINARY ?= bell
BUILD_DIR ?= build
OUTPUT ?= $(BUILD_DIR)/$(BINARY)
CMD_PKG ?= ./cmd/bellbird
PIPELINE_SCRIPT ?= ./scripts/podman-pipeline.sh
VERIFY_SCRIPT ?= ./scripts/verification-tests.sh

INSTALL_NAME ?= bell
INSTALL_ROOT_DIR ?= /bin

IMAGE ?= sl.urutau-ltd.org/urutau-ltd/bellbird:latest
IMAGE_PLATFORM ?= linux/amd64

LDFLAGS ?= -s -w -buildid=

GIT_COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
GIT_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
BUILD_VERSION ?= $(GIT_TAG)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
UPSTREAM_REPO ?= urutau-ltd/bellbird
UPSTREAM_VENDOR ?= Urutau Limited
BUILD_LDFLAGS ?= \
	-X 'main.buildVersion=$(BUILD_VERSION)' \
	-X 'main.buildTag=$(GIT_TAG)' \
	-X 'main.buildCommit=$(GIT_COMMIT)' \
	-X 'main.buildDate=$(BUILD_DATE)' \
	-X 'main.upstreamRepo=$(UPSTREAM_REPO)' \
	-X 'main.upstreamVendor=$(UPSTREAM_VENDOR)'
BUILD_FLAGS ?= $(BUILD_LDFLAGS)

FUZZTIME ?= 5s
GO_SOURCES := $(shell find . -type f -name '*.go' -not -path './vendor/*')
HAS_GCC := $(shell command -v gcc >/dev/null 2>&1 && gcc -v >/dev/null 2>&1 && echo yes || echo no)

# FIXME: This is DIRTY, find a proper way to do this.
GCC_TOOLCHAIN_BIN := $(firstword $(wildcard /gnu/store/*-gcc-toolchain-*/bin))
GCC_TOOLCHAIN_ROOT := $(patsubst %/bin,%,$(GCC_TOOLCHAIN_BIN))
GCC_TOOLCHAIN_LIB := $(GCC_TOOLCHAIN_ROOT)/lib
GCC_TOOLCHAIN_INCLUDE := $(GCC_TOOLCHAIN_ROOT)/include

.PHONY: fmt fmt-check vet test test-race ci build install run clean image compose-up compose-down compose-logs env pkg e2e verify proof pipeline pipeline-ci pipeline-build pipeline-e2e pipeline-verify pipeline-proof

fmt:
	@gofmt -w $(GO_SOURCES)

fmt-check:
	@UNFORMATTED="$$(gofmt -l $(GO_SOURCES))"; \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "Files not formatted with gofmt:"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi

vet:
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) $(GO) vet ./...

test:
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) $(GO) test -v ./...

test-race:
ifneq ($(GCC_TOOLCHAIN_BIN),)
	PATH="$(GCC_TOOLCHAIN_BIN):$$PATH" \
	LIBRARY_PATH="$(GCC_TOOLCHAIN_LIB):$$LIBRARY_PATH" \
	LD_LIBRARY_PATH="$(GCC_TOOLCHAIN_LIB):$$LD_LIBRARY_PATH" \
	CPATH="$(GCC_TOOLCHAIN_INCLUDE):$$CPATH" \
	CGO_ENABLED=$(RACE_CGO_ENABLED) CC=gcc GOCACHE=$(GOCACHE) $(GO) test -race ./...
else ifeq ($(HAS_GCC),yes)
	CGO_ENABLED=$(RACE_CGO_ENABLED) CC=gcc GOCACHE=$(GOCACHE) $(GO) test -race ./...
else
	@echo "Skipping race tests: gcc not found in PATH"
endif

ci: fmt-check vet test test-race

build:
	mkdir -p $(dir $(OUTPUT))
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) $(GO) build -trimpath -ldflags "$(LDFLAGS) $(BUILD_FLAGS)" -o $(OUTPUT) $(CMD_PKG)

run:
	@podman compose up -d --force-recreate

stop:
	@podman compose down

install:
	install -d "$(INSTALL_ROOT_DIR)"
	install -m 0755 "$(OUTPUT)" "$(INSTALL_ROOT_DIR)/$(INSTALL_NAME)"

clean:
	rm -rf $(BUILD_DIR)

image:
	podman build --target runtime --platform $(IMAGE_PLATFORM) \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=$$(echo "$(IMAGE_PLATFORM)" | awk -F/ '{if ($$2 == "") print $$1; else print $$2}') \
		--build-arg BUILD_VERSION=$(BUILD_VERSION) \
		--build-arg BUILD_TAG=$(GIT_TAG) \
		--build-arg BUILD_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg UPSTREAM_REPO=$(UPSTREAM_REPO) \
		--build-arg UPSTREAM_VENDOR=$(UPSTREAM_VENDOR) \
		-t $(IMAGE) .

compose-up:
	@podman compose up -d --force-recreate --build

compose-down:
	@podman compose down

compose-logs:
	@podman compose logs -f --tail=100

env:
	guix shell --network -m ./manifest.scm

pkg:
	@test -f ./guix.scm || { \
		echo "guix.scm is not in this repository yet. Use 'make env' for the shell workflow."; \
		exit 1; \
	}
	guix build -f ./guix.scm

e2e: build
	./$(OUTPUT) selftest

verify: ci build
	$(VERIFY_SCRIPT) ./$(OUTPUT)

proof: verify

pipeline:
	$(PIPELINE_SCRIPT) all

pipeline-ci:
	$(PIPELINE_SCRIPT) ci

pipeline-build:
	$(PIPELINE_SCRIPT) build

pipeline-e2e:
	$(PIPELINE_SCRIPT) e2e

pipeline-verify:
	$(PIPELINE_SCRIPT) verify

pipeline-proof:
	$(PIPELINE_SCRIPT) verify
