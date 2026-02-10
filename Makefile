CLANG ?= clang-19
CFLAGS ?= -O2 -g -Wall -Werror
GOARCH ?= amd64

LIBEBPF_TOP = ${PWD}
HEADERS = $(LIBEBPF_TOP)/bpf/headers

DOCKER_COMPOSE_TEST = docker compose -f docker-compose.test.yml

.PHONY: all generate build clean \
	docker-build-test test-unit test-rego test-ebpf test-integration test-all \
	test-unit-local test-rego-local test-clean

# =====================
# Build Targets
# =====================

all: generate build

generate: export BPF_CLANG=$(CLANG)
generate: export BPF_CFLAGS=$(CFLAGS)
generate: export BPF_HEADERS=$(HEADERS)

generate:
	@echo "Running go generate to build eBPF code..."
	go generate ./...

build:
	@echo "Download the github metadata to the OPA bundle..."
	wget -q --timeout=30 --tries=3 https://api.github.com/meta -O ./bundle/assets/github/data.json

	@echo "Building the project..."
	go build -o kntrl .

clean:
	rm -f kntrl ./internal/handlers/tracer/bpf_bpfel_x86.o ./internal/handlers/tracer/bpf_bpfel_x86.go

# =====================
# Docker Test Targets
# =====================

# Build the test Docker image (cached)
docker-build-test:
	$(DOCKER_COMPOSE_TEST) build

# Run unit tests (no eBPF needed, safe on any platform)
test-unit:
	$(DOCKER_COMPOSE_TEST) run --rm test-unit

# Run OPA/Rego tests
test-rego:
	$(DOCKER_COMPOSE_TEST) run --rm test-rego

# Run eBPF tests (requires Linux kernel access via Docker)
test-ebpf:
	$(DOCKER_COMPOSE_TEST) run --rm test-ebpf

# Run integration tests (requires Linux kernel access via Docker)
test-integration:
	$(DOCKER_COMPOSE_TEST) run --rm test-integration

# Run ALL tests in Docker
test-all:
	$(DOCKER_COMPOSE_TEST) run --rm test-all

# Internal target used inside Docker container
test-all-docker:
	@echo "=== Running Rego tests ==="
	opa test -v ./bundle/...
	@echo "=== Running unit tests ==="
	go test -v -count=1 ./pkg/... ./internal/core/...
	@echo "=== Running eBPF tests ==="
	go test -v -count=1 -tags=ebpf -timeout=120s ./internal/handlers/tracer/... ./pkg/ebpf/...
	@echo "=== All tests passed ==="

# =====================
# Local Test Targets (no Docker)
# =====================

# Run unit tests locally (no Docker, works on macOS)
test-unit-local:
	go test -v -count=1 ./pkg/config/... ./pkg/policy/... ./pkg/reporter/... ./pkg/utils/... ./pkg/parser/... ./internal/core/...

# Run Rego tests locally (requires opa CLI)
test-rego-local:
	opa test -v ./bundle/...

# =====================
# Cleanup
# =====================

# Cleanup test containers and images
test-clean:
	$(DOCKER_COMPOSE_TEST) down --rmi local --volumes --remove-orphans
