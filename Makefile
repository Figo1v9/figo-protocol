# Makefile for FGXP (FigoX Protocol) project

.PHONY: all build test clean fmt vet run-server run-client docker-build

# Variables
BINARY_DIR=bin
SERVER_BINARY=$(BINARY_DIR)/fgxp-server
CLIENT_BINARY=$(BINARY_DIR)/fgxp-client
BENCH_BINARY=$(BINARY_DIR)/fgxp-bench

all: fmt vet test build

build:
	@echo "Building binaries..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(SERVER_BINARY) ./cmd/fgxp-server
	go build -o $(CLIENT_BINARY) ./cmd/fgxp-client
	go build -o $(BENCH_BINARY) ./cmd/fgxp-bench
	@echo "Binaries saved to $(BINARY_DIR)/"

test:
	@echo "Running tests..."
	go test ./pkg/... ./internal/... -v -race -count=1
	@echo "Running integration tests..."
	go test ./test/integration/... -v -count=1

fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Running go vet..."
	go vet ./...

clean:
	@echo "Cleaning binaries..."
	rm -rf $(BINARY_DIR)

run-server: build
	./$(SERVER_BINARY) --listen :8443 --psk "secret"

run-client: build
	./$(CLIENT_BINARY) --server 127.0.0.1:8443 --psk "secret" --sni "localhost"

docker-build:
	docker build -t fgxp:latest .
