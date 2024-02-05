CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror 
GOARCH ?= amd64

LIBEBPF_TOP = ${PWD}
HEADERS = $(LIBEBPF_TOP)/bpf/headers

all: generate build 

generate: export BPF_CLANG=$(CLANG)
generate: export BPF_CFLAGS=$(CFLAGS)
generate: export BPF_HEADERS=$(HEADERS)
generate:
	go generate ./...
build:
	go build -o kntrl .
clean:
	rm kntrl ./internal/handlers/prevent/bpf_bpfel_x86.o ./internal/handlers/prevent/bpf_bpfel_x86.go ./internal/handlers/monitor/bpf_bpfel_x86.o ./internal/handlers/monitor/bpf_bpfel_x86.go
