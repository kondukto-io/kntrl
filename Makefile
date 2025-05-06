CLANG ?= clang-19
CFLAGS ?= -O2 -g -Wall -Werror 
GOARCH ?= amd64

LIBEBPF_TOP = ${PWD}
HEADERS = $(LIBEBPF_TOP)/bpf/headers

.PHONY: all generate build clean

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
	rm kntrl ./internal/handlers/tracer/bpf_bpfel_x86.o ./internal/handlers/tracer/bpf_bpfel_x86.go
