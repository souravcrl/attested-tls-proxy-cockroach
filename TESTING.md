# Integration Testing Guide

This guide provides step-by-step instructions for running integration tests with the Attested TLS Proxy and CockroachDB.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Test Architecture](#test-architecture)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required

1. **Go 1.21 or later**
   ```bash
   go version
   ```

2. **OpenSSL** (for SEV-SNP simulation)

   **macOS (Homebrew):**
   ```bash
   brew install openssl@3
   export CGO_CFLAGS="-I/opt/homebrew/Cellar/openssl@3/3.5.0/include"
   export CGO_LDFLAGS="-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib -lcrypto"
   ```

   **Linux:**
   ```bash
   sudo apt-get install libssl-dev
   ```

### Optional (for E2E tests)

3. **CockroachDB** (for end-to-end database tests)

   **macOS:**
   ```bash
   brew install cockroachdb/tap/cockroach
   ```

   **Linux:**
   ```bash
   curl https://binaries.cockroachdb.com/cockroach-latest.linux-amd64.tgz | tar -xz
   sudo cp -i cockroach-latest.linux-amd64/cockroach /usr/local/bin/
   ```

   Verify installation:
   ```bash
   cockroach version
   ```

## Quick Start

### 1. Clone and Build

```bash
cd /path/to/attested-tls-proxy-cockroach
make build
```

### 2. Run All Tests

```bash
./tests/integration/run-e2e.sh all
```

### 3. Run Specific Test Suites

```bash
# Run only unit tests
./tests/integration/run-e2e.sh unit

# Run only integration tests (no CockroachDB required)
./tests/integration/run-e2e.sh integration

# Run only E2E tests (requires CockroachDB)
./tests/integration/run-e2e.sh e2e
```

## Test Architecture

The testing framework consists of several layers:

### Test Client (`tests/integration/testclient/`)

Simulated client that can generate attestation evidence and connect to the proxy.

**Key Features:**
- Generates mock SEV-SNP attestation reports
- Creates X.509 certificates with attestation extensions
- Supports TLS 1.3 connections
- PostgreSQL wire protocol support

**Pre-configured Evidence Generators:**
```go
// Valid attestation
evidence, _ := testclient.DefaultValidEvidence()

// Debug mode enabled
evidence, _ := testclient.WithDebugEnabled()

// SMT enabled
evidence, _ := testclient.WithSMTEnabled()

// Invalid measurement
evidence, _ := testclient.WithInvalidMeasurement()

// Expired nonce
evidence, _ := testclient.WithExpiredNonce()
```

### Test Helpers (`tests/integration/helpers/`)

Utilities for managing test environments.

**Proxy Management (`helpers/proxy.go`):**
```go
// Start test proxy
proxy, err := helpers.StartTestProxy(cfg)
defer proxy.Stop()

// Get proxy address
addr := proxy.GetAddr() // e.g., "localhost:12345"
```

**CockroachDB Management (`helpers/crdb.go`):**
```go
// Start CRDB instance
crdb, err := helpers.StartTestCRDB()
defer crdb.Stop()

// Wait for CRDB to be ready
err = helpers.WaitForCRDB(crdb, 30)

// Create database
crdb.CreateDatabase("testdb")

// Create user
crdb.CreateUser("testuser", "password")

// Execute SQL
crdb.ExecuteSQL("CREATE TABLE users (id INT PRIMARY KEY)")
```

**Test Environment Setup (`helpers/setup.go`):**
```go
// Setup without CockroachDB (proxy only)
env := helpers.SetupTestEnv(t, policyFile)
defer env.Cleanup()

// Setup with CockroachDB
env := helpers.SetupTestEnvWithCRDB(t, policyFile)
defer env.Cleanup()

// Access components
env.Proxy   // Test proxy instance
env.CRDB    // Test CockroachDB instance (if using SetupTestEnvWithCRDB)
env.Client  // Test client
env.Config  // Configuration
```

### Test Fixtures (`tests/integration/fixtures/policies/`)

Policy files for different test scenarios:

- **`strict-test.yaml`** - Strict enforcement (all checks must pass)
- **`warn-test.yaml`** - Warning mode (violations logged, not enforced)
- **`disabled-test.yaml`** - Disabled mode (all checks disabled)
- **`debug-allowed-test.yaml`** - Allows debug mode for development

## Running Tests

### Integration Tests (No CockroachDB)

These tests verify attestation policy enforcement without requiring a database:

```bash
cd tests/integration
go test -v -run "Test(Valid|Invalid|Debug|SMT|Expired|Warn|Disabled)" .
```

**Test Coverage:**
- Valid attestation acceptance
- Invalid measurement rejection
- Debug mode policy enforcement
- SMT policy enforcement
- Expired nonce rejection
- Warn mode behavior
- Disabled mode behavior

### E2E Tests (With CockroachDB)

These tests verify complete end-to-end functionality including SQL queries:

```bash
cd tests/integration
go test -v -run "TestE2E" .
```

**Test Coverage:**
- Basic SQL queries through proxy
- Table creation and data insertion
- Rejected clients cannot query
- Multiple concurrent clients

### Running Individual Tests

```bash
# Run a single test
go test -v -run TestValidAttestation .

# Run tests with verbose output
go test -v .

# Run tests with race detection
go test -race .
```

## Writing Tests

### Basic Integration Test

```go
package integration

import (
    "testing"
    "github.com/souravcrl/attested-tls-proxy-cockroach/tests/integration/helpers"
    "github.com/souravcrl/attested-tls-proxy-cockroach/tests/integration/testclient"
)

func TestMyAttestation(t *testing.T) {
    // Setup environment
    policyPath := helpers.GetPolicyPath("strict-test.yaml")
    env := helpers.SetupTestEnv(t, policyPath)
    defer env.Cleanup()

    // Create attestation evidence
    evidence, err := testclient.DefaultValidEvidence()
    if err != nil {
        t.Fatalf("Failed to create evidence: %v", err)
    }

    // Generate certificate
    err = env.Client.GenerateCertificate(evidence)
    if err != nil {
        t.Fatalf("Failed to generate certificate: %v", err)
    }

    // Connect to proxy
    conn, err := env.Client.Connect(env.Proxy.GetAddr())
    if err != nil {
        t.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()

    t.Log("Test passed")
}
```

### E2E Test with Database

```go
func TestMyE2EQuery(t *testing.T) {
    // Skip if CockroachDB not available
    if !helpers.IsCockroachInstalled() {
        t.Skip("CockroachDB not installed")
    }

    // Setup with CockroachDB
    policyPath := helpers.GetPolicyPath("strict-test.yaml")
    env := helpers.SetupTestEnvWithCRDB(t, policyPath)
    defer env.Cleanup()

    // Create attestation
    evidence, _ := testclient.DefaultValidEvidence()
    env.Client.GenerateCertificate(evidence)

    // Connect to database through proxy
    clientCfg := &testclient.ClientConfig{
        ServerAddr: env.Proxy.GetAddr(),
        Database:   "defaultdb",
        User:       "root",
    }
    env.Client.ConnectDB(clientCfg)

    // Execute query
    var result int
    env.Client.QueryRow("SELECT 1").Scan(&result)

    if result != 1 {
        t.Fatalf("Expected 1, got %d", result)
    }
}
```

### Custom Evidence Test

```go
func TestCustomEvidence(t *testing.T) {
    // Create custom attestation parameters
    var measurement [48]byte
    copy(measurement[:], []byte("MY_CUSTOM_MEASUREMENT"))

    evidence, err := testclient.CreateMockEvidence(testclient.AttestationParams{
        Measurement:     measurement,
        DebugEnabled:    false,
        SMTEnabled:      false,
        TCBVersion:      "1.51.0",
        GuestSVN:        1,
        PlatformVersion: 1,
    })
    if err != nil {
        t.Fatalf("Failed to create evidence: %v", err)
    }

    // Use the evidence in your test...
}
```

## Test Policies

### Strict Policy

Enforces all security requirements:

```yaml
version: "1.0"
measurements:
  expected: "544553545f4d4541535552454d454e545f56414c49445f30303100..."
  mode: "strict"  # Reject on mismatch
tcb:
  min_version: "1.51.0"
  mode: "strict"
guest:
  debug_disabled: true  # Reject if debug enabled
  smt_disabled: true    # Reject if SMT enabled
  mode: "strict"
```

### Warn Policy

Logs violations but allows connections:

```yaml
measurements:
  mode: "warn"  # Log but don't reject
tcb:
  mode: "warn"
guest:
  mode: "warn"
certificates:
  verify_signature: false  # Skip signature verification
```

### Development Policy

Permissive for development:

```yaml
measurements:
  mode: "disabled"
guest:
  debug_disabled: false  # Allow debug mode
  mode: "disabled"
```

## Troubleshooting

### Build Errors

**Error: `library 'crypto' not found`**

Set CGo environment variables:

```bash
# macOS
export CGO_CFLAGS="-I/opt/homebrew/Cellar/openssl@3/3.5.0/include"
export CGO_LDFLAGS="-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib -lcrypto"

# Linux
export CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lcrypto"
```

### Test Failures

**CockroachDB won't start:**

```bash
# Check if port is in use
lsof -i :26257

# Kill existing processes
pkill -f cockroach

# Clean up old data
rm -rf /tmp/crdb-test-*
```

**Proxy connection refused:**

```bash
# Check if port is available
lsof -i :12345

# Verify proxy is running
ps aux | grep atls-proxy
```

**TLS handshake failures:**

- Verify client certificate has attestation extension
- Check policy file is valid YAML
- Ensure TLS 1.3 is enabled
- Check server logs for specific errors

### Logging

Enable debug logging:

```bash
# Set log level in config
export LOG_LEVEL=debug

# Or in code
config.Logging.Level = "debug"
```

View proxy logs during tests:

```go
// In your test
env := helpers.SetupTestEnv(t, policyFile)
// Proxy logs will appear in test output with -v flag
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libssl-dev

      - name: Run integration tests
        run: ./tests/integration/run-e2e.sh integration

      - name: Install CockroachDB
        run: |
          wget -qO- https://binaries.cockroachdb.com/cockroach-latest.linux-amd64.tgz | tar xz
          sudo cp -i cockroach-latest.linux-amd64/cockroach /usr/local/bin/

      - name: Run E2E tests
        run: ./tests/integration/run-e2e.sh e2e
```

## Performance Testing

### Benchmark Tests

```go
func BenchmarkAttestation(b *testing.B) {
    env := helpers.SetupTestEnv(b, "strict-test.yaml")
    defer env.Cleanup()

    evidence, _ := testclient.DefaultValidEvidence()
    env.Client.GenerateCertificate(evidence)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        conn, _ := env.Client.Connect(env.Proxy.GetAddr())
        conn.Close()
    }
}
```

Run benchmarks:

```bash
go test -bench=. -benchmem
```

## Additional Resources

- [BUILD.md](BUILD.md) - Build instructions
- [README.md](README.md) - Project overview
- [AMD SEV-SNP Documentation](https://www.amd.com/en/developer/sev.html)
- [RFC 9261 - Exported Authenticators](https://www.rfc-editor.org/rfc/rfc9261.html)