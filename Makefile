.PHONY: build test clean run fmt lint help

# Binary name
BINARY_NAME=atls-proxy
BUILD_DIR=bin
MAIN_PATH=./cmd/proxy

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Build flags
LDFLAGS=-ldflags "-s -w"

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build the proxy binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

run: build ## Build and run the proxy with dev config
	@echo "Starting proxy..."
	./$(BUILD_DIR)/$(BINARY_NAME) --config config/dev.yaml

test: ## Run all tests
	@echo "Running tests..."
	$(GOTEST) -v -race ./...

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	$(GOTEST) -v -short ./...

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	$(GOTEST) -v -run Integration ./tests/integration/...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

fmt: ## Format Go code
	@echo "Formatting code..."
	$(GOFMT) ./...

lint: ## Run linters
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found, install it from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

tidy: ## Tidy Go modules
	@echo "Tidying modules..."
	$(GOMOD) tidy

clean: ## Clean build artifacts
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

install: build ## Install the binary to $GOPATH/bin
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

# Docker targets
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t attested-tls-proxy:latest .

# Deployment targets
deploy-local: ## Deploy CRDB and proxy locally for testing
	@echo "Deploying local test environment..."
	./scripts/deploy_local.sh

deploy-gcp: ## Deploy to GCP SEV-SNP VM
	@echo "Deploying to GCP..."
	cd iac/terraform && terraform apply

# Measurement targets
generate-measurements: build ## Generate binary measurements for policy
	@echo "Generating measurements..."
	./scripts/generate_measurements.sh

# Development helpers
dev-setup: ## Setup development environment
	@echo "Setting up development environment..."
	$(GOMOD) download
	@which golangci-lint > /dev/null || echo "Consider installing golangci-lint: https://golangci-lint.run/usage/install/"
	@mkdir -p config certs logs

all: clean fmt lint test build ## Run all checks and build