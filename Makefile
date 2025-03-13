CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

ifeq (,$(shell which goimports))
$(shell go install golang.org/x/tools/cmd/goimports@latest)
GO_IMPORTS=$(shell which goimports)
else
GO_IMPORTS=$(shell which goimports)
endif

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: generate-ebpf
generate-ebpf: export BPF_CLANG := $(CLANG)
generate-ebpf: export BPF_CFLAGS := $(CFLAGS)
generate-ebpf: ## Generate the ebpf code and lib
	go generate ./...

.PHONY: fmt
fmt: ## Run go fmt against code.
	@echo "[+] Run go fmt against code."
	go fmt ./... && $(GO_IMPORTS) -w ./

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test-unit
test-unit: ## Run unit tests
	@echo "	running unit tests"
	go test ./... -coverprofile coverage.out

.PHONY: test
test: test-unit ## Run tests.

.PHONY: build
build: generate-ebpf fmt vet
