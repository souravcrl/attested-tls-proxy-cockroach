#!/usr/bin/env bash
# End-to-End Test Runner for Attested TLS Proxy
# This script sets up a complete test environment and runs integration tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print with color
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if CockroachDB is installed
check_cockroach() {
    if command -v cockroach &> /dev/null; then
        COCKROACH_VERSION=$(cockroach version | head -n1)
        print_info "CockroachDB found: $COCKROACH_VERSION"
        return 0
    else
        print_warning "CockroachDB not found. E2E database tests will be skipped."
        print_info "Install CockroachDB from: https://www.cockroachlabs.com/docs/stable/install-cockroachdb.html"
        return 1
    fi
}

# Check if Go is installed
check_go() {
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version)
        print_info "Go found: $GO_VERSION"
        return 0
    else
        print_error "Go not found. Please install Go 1.21 or later."
        exit 1
    fi
}

# Check if OpenSSL is installed (for macOS)
check_openssl_mac() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if [[ -d "/opt/homebrew/Cellar/openssl@3" ]]; then
            OPENSSL_VERSION=$(openssl version)
            print_info "OpenSSL found: $OPENSSL_VERSION"

            # Set CGo flags for macOS
            export CGO_CFLAGS="-I/opt/homebrew/Cellar/openssl@3/3.5.0/include"
            export CGO_LDFLAGS="-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib -lcrypto"
            print_info "CGo flags set for macOS OpenSSL"
            return 0
        else
            print_warning "OpenSSL not found in Homebrew. Trying system OpenSSL..."
        fi
    fi
    return 0
}

# Clean up any previous test artifacts
cleanup() {
    print_info "Cleaning up test artifacts..."
    rm -rf /tmp/crdb-test-*
    pkill -f "cockroach start-single-node" || true
    print_info "Cleanup complete"
}

# Run unit tests
run_unit_tests() {
    print_info "Running unit tests..."
    go test -v -short ./pkg/... ./internal/...
    print_info "Unit tests passed"
}

# Run integration tests (proxy only, no CRDB)
run_integration_tests() {
    print_info "Running integration tests (proxy only)..."
    cd tests/integration
    go test -v -run "Test(Valid|Invalid|Debug|SMT|Expired|Warn|Disabled)" .
    cd ../..
    print_info "Integration tests passed"
}

# Run E2E tests (with CRDB)
run_e2e_tests() {
    if check_cockroach; then
        print_info "Running E2E tests (with CockroachDB)..."
        cd tests/integration
        go test -v -run "TestE2E" .
        cd ../..
        print_info "E2E tests passed"
    else
        print_warning "Skipping E2E tests (CockroachDB not available)"
    fi
}

# Run all tests
run_all_tests() {
    run_unit_tests
    run_integration_tests
    run_e2e_tests
}

# Main execution
main() {
    print_info "=== Attested TLS Proxy E2E Test Runner ==="

    # Check prerequisites
    check_go
    check_openssl_mac

    # Parse command line arguments
    TEST_TYPE=${1:-all}

    case "$TEST_TYPE" in
        unit)
            run_unit_tests
            ;;
        integration)
            run_integration_tests
            ;;
        e2e)
            run_e2e_tests
            ;;
        all)
            run_all_tests
            ;;
        clean)
            cleanup
            ;;
        *)
            print_error "Unknown test type: $TEST_TYPE"
            echo "Usage: $0 [unit|integration|e2e|all|clean]"
            echo "  unit        - Run unit tests only"
            echo "  integration - Run integration tests (proxy only)"
            echo "  e2e         - Run E2E tests (with CockroachDB)"
            echo "  all         - Run all tests (default)"
            echo "  clean       - Clean up test artifacts"
            exit 1
            ;;
    esac

    print_info "=== Tests Complete ==="
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main
main "$@"