# Attested TLS Proxy Implementation Plan

## Executive Summary

This document outlines the implementation plan for building a TEE-based attested TLS proxy for CockroachDB. The project progresses through 5 phases, starting with a proxy-only TEE architecture (Phases 1-3) and evolving to a full-stack TEE solution (Phase 4) where both proxy and CockroachDB run in the same SEV-SNP environment.

## Architectural Evolution

### Understanding the Attestation Scope

#### Phase 1-3: Distributed Attestation with Centralized Dashboard
```
┌─────────────┐                                    ┌─────────────┐
│ Client      │                                    │ Client      │
│ (SEV-SNP)   │                                    │ (SEV-SNP)   │
└──────┬──────┘                                    └──────┬──────┘
       │ aTLS (Client attests to Proxy)                  │ aTLS
       │                                                  │
       ▼                                                  ▼
┌──────────────────────┐                    ┌──────────────────────┐
│   TEE VM 1           │                    │   TEE VM 2           │
│  ┌───────┐ ┌──────┐ │                    │  ┌───────┐ ┌──────┐ │
│  │Proxy 1│─│CRDB 1│ │                    │  │Proxy 2│─│CRDB 2│ │
│  │:26257 │ │:26258│ │                    │  │:26257 │ │:26258│ │
│  │       │ │      │ │                    │  │       │ │      │ │
│  │ API   │ │      │ │                    │  │ API   │ │      │ │
│  │:8080  │ │      │ │                    │  │:8080  │ │      │ │
│  └───┬───┘ └──────┘ │                    │  └───┬───┘ └──────┘ │
│      │ Attestation  │                    │      │ Attestation  │
│      │ Store (Local)│                    │      │ Store (Local)│
└──────┼──────────────┘                    └──────┼──────────────┘
       │ HTTP API                                 │ HTTP API
       │ /api/v1/attestations                     │ /api/v1/attestations
       │ /api/v1/clients                          │ /api/v1/clients
       │                                           │
       └────────────────┬──────────────────────────┘
                        │ Pull-based queries
                        ▼
                ┌─────────────────────┐
                │  Dashboard (Web UI) │
                │  - Query all proxies│
                │  - Aggregate data   │
                │  - Visualize cluster│
                └─────────────────────┘
```

**Architecture Principles:**
- **Co-located**: Each CRDB node has its own proxy in the same TEE VM
- **Local Storage**: Each proxy stores attestation data locally (SQLite/in-memory)
- **HTTP API**: Each proxy exposes REST API for attestation data
- **Pull-based**: Dashboard queries all proxy nodes on-demand
- **Stateless Aggregation**: Dashboard aggregates responses in real-time

**What This Attests:**
- **Clients**: Client software integrity, measurements, security configuration
- **Proxy**: Each proxy's software integrity and policy enforcement
- **CRDB Nodes**: Database node integrity via co-location with attested proxy
- **Complete Data Path**: End-to-end cryptographic verification

**Protects Against:**
- Compromised proxy or database software
- Compromised or unauthorized clients
- Rogue nodes joining the cluster
- Man-in-the-middle attacks
- Policy bypass attempts
- Unauthorized client connections

**Centralized Monitoring Benefits:**
- **Unified View**: Dashboard queries all proxies and presents aggregate data
- **Client Inventory**: Cluster-wide tracking of all connected clients with attestation status
- **Node Topology**: Visual map of CRDB cluster with per-node health
- **Historical Data**: Time-series attestation metrics per proxy
- **Anomaly Detection**: Cluster-wide measurement drift alerts
- **Real-time**: On-demand queries show current cluster state

**HTTP API Design:**
```
GET /api/v1/attestations              # List all attestation events
GET /api/v1/attestations/{id}         # Get specific attestation
GET /api/v1/clients                   # List currently connected clients
GET /api/v1/clients/{id}/attestation  # Get client's attestation details
GET /api/v1/metrics                   # Prometheus-style metrics
GET /api/v1/health                    # Proxy health + CRDB status
```

**Dashboard Features:**
- Discover proxy nodes (manual config or CRDB node list)
- Query all proxies in parallel
- Aggregate and deduplicate client data
- Show cluster topology (which clients connect to which nodes)
- Filter by time range, client ID, measurement hash
- Export compliance reports (CSV, JSON)

**Use Cases:**
- Compliance gateway with comprehensive audit trail
- Zero-trust client verification before database access
- Multi-tenant isolation with per-client attestation tracking
- Secure cluster expansion with automated node verification
- Real-time security posture monitoring

#### Phase 4: Full-Stack TEE (Per-Node)
```
┌─────────┐   aTLS    ┌────────────────────────────────┐
│ Client  │ ────────> │    SEV-SNP VM (TEE)            │
│         │           │  ┌──────┐      ┌──────────┐    │
└─────────┘           │  │Proxy │ ───> │CockroachDB│   │
                      │  │:26257│ Unix │(localhost)│   │
                      │  └──────┘ Sock └──────────┘    │
                      └────────────────────────────────┘
                              Both Attested
```

**What This Attests:**
- Complete data processing pipeline
- Both proxy and database integrity
- Query execution environment

**Additional Protection:**
- End-to-end attestation of entire data path
- Database memory protected from host OS
- Query execution in confidential computing environment

---

## Phase 1: Local Development & Attestation Foundation (2-3 weeks)

### 1.1 Project Setup & Structure

**Objective:** Establish development environment and project skeleton

**Directory Structure:**
```
attested-tls-proxy-cockroach/
├── cmd/
│   └── proxy/
│       └── main.go                 # Proxy entry point
├── pkg/
│   ├── attestation/
│   │   ├── sev_snp.go             # SEV-SNP attestation
│   │   ├── sev_snp.c              # CGo bindings
│   │   └── types.go               # Attestation types
│   ├── tls/
│   │   ├── exported_auth.go       # RFC 9261 implementation
│   │   └── attestation_extension.go # EAT in TLS extension
│   ├── policy/
│   │   ├── verifier.go            # Measurement verification
│   │   └── policy.go              # Policy engine
│   ├── backend/
│   │   ├── cockroach.go           # CockroachDB connection
│   │   └── pool.go                # Connection pooling
│   └── auth/
│       ├── sts_client.go          # Token exchange
│       └── authenticator.go       # Request authentication
├── internal/
│   ├── config/
│   │   └── config.go              # Configuration loading
│   └── logger/
│       └── logger.go              # Structured logging
├── config/
│   ├── dev.yaml                   # Local development
│   ├── proxy.example.yaml         # Production example
│   └── policy.yaml                # Attestation policy
├── scripts/
│   ├── generate_measurements.sh   # Measurement generation
│   └── deploy_crdb.sh             # CRDB deployment
├── iac/
│   └── terraform/
│       ├── main.tf                # GCP infrastructure
│       └── variables.tf           # Configuration variables
├── tests/
│   ├── unit/                      # Unit tests
│   ├── integration/               # Integration tests
│   └── e2e/                       # End-to-end tests
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   ├── DEVELOPMENT.md
│   └── TROUBLESHOOTING.md
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

**Tasks:**
- [ ] Initialize Go module: `go mod init github.com/souravcrl/attested-tls-proxy-cockroach`
- [ ] Create directory structure
- [ ] Setup Makefile with targets:
  - `make build` - Build proxy binary
  - `make test` - Run all tests
  - `make test-unit` - Unit tests only
  - `make test-integration` - Integration tests
  - `make lint` - Run linters
  - `make fmt` - Format code
  - `make clean` - Clean build artifacts
- [ ] Configure CI/CD (GitHub Actions):
  - Run tests on PR
  - Run linters
  - Build multi-arch binaries
  - Generate coverage reports
- [ ] Setup development tools:
  - golangci-lint configuration
  - pre-commit hooks
  - VS Code/GoLand settings

**Dependencies:**
```bash
go get github.com/jackc/pgproto3/v2      # PostgreSQL protocol
go get gopkg.in/yaml.v3                  # YAML parsing
go get github.com/rs/zerolog             # Structured logging
go get github.com/prometheus/client_golang # Metrics
go get github.com/stretchr/testify       # Testing utilities
```

**Deliverable:** Basic project skeleton with CI pipeline

**Success Criteria:**
- `make build` produces working binary
- `make test` passes with empty test suite
- CI pipeline runs successfully

---

### 1.2 Core TLS Proxy Implementation (No Attestation)

**Objective:** Build a functional TCP proxy that forwards PostgreSQL wire protocol traffic to CockroachDB

**File:** `cmd/proxy/main.go`
```go
package main

import (
    "flag"
    "log"
    "github.com/souravcrl/attested-tls-proxy-cockroach/internal/config"
    "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/backend"
)

func main() {
    configPath := flag.String("config", "config/dev.yaml", "Config file path")
    flag.Parse()

    cfg, err := config.Load(*configPath)
    if err != nil {
        log.Fatal(err)
    }

    proxy := backend.NewProxy(cfg)
    if err := proxy.Start(); err != nil {
        log.Fatal(err)
    }
}
```

**File:** `pkg/backend/cockroach.go`
```go
package backend

import (
    "crypto/tls"
    "net"
    "github.com/jackc/pgproto3/v2"
)

type Proxy struct {
    listener net.Listener
    backend  *ConnectionPool
}

func (p *Proxy) Start() error {
    // Listen on 26257
    // Accept connections
    // For each connection:
    //   - Parse PostgreSQL startup message
    //   - Establish backend connection to CRDB
    //   - Forward messages bidirectionally
}

func (p *Proxy) handleConnection(clientConn net.Conn) {
    // PostgreSQL wire protocol handling
    frontend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)

    // Read startup message
    startupMessage, err := frontend.ReceiveStartupMessage()

    // Connect to backend CRDB
    backendConn, err := p.backend.Get()

    // Bidirectional forwarding
    go p.forwardClientToBackend(clientConn, backendConn)
    go p.forwardBackendToClient(backendConn, clientConn)
}
```

**File:** `internal/config/config.go`
```go
package config

type Config struct {
    Proxy struct {
        Listen  string `yaml:"listen"`
        Backend struct {
            Host string `yaml:"host"`
            Port int    `yaml:"port"`
            TLS  struct {
                Enabled bool   `yaml:"enabled"`
                CACert  string `yaml:"ca_cert"`
            } `yaml:"tls"`
        } `yaml:"backend"`
    } `yaml:"proxy"`

    Logging struct {
        Level     string `yaml:"level"`
        AuditFile string `yaml:"audit_file"`
    } `yaml:"logging"`
}

func Load(path string) (*Config, error) {
    // Read YAML file
    // Parse into Config struct
    // Validate required fields
}
```

**Configuration:** `config/dev.yaml`
```yaml
proxy:
  listen: "0.0.0.0:26257"
  backend:
    host: "localhost"
    port: 26258  # CRDB running on different port for testing
    tls:
      enabled: false

logging:
  level: "debug"
  audit_file: "/tmp/proxy-audit.json"
```

**Tasks:**
- [ ] Implement TCP listener on configurable port
- [ ] Parse PostgreSQL wire protocol (startup message, queries, responses)
- [ ] Establish backend connection pool to CockroachDB
- [ ] Implement bidirectional message forwarding
- [ ] Add basic TLS support (standard `crypto/tls`, no attestation yet)
- [ ] Implement graceful shutdown
- [ ] Add connection lifecycle logging

**Testing Strategy:**
```bash
# Terminal 1: Start CockroachDB on non-standard port
cockroach start-single-node --insecure --listen-addr=localhost:26258

# Terminal 2: Start proxy
./bin/proxy --config config/dev.yaml

# Terminal 3: Test connection through proxy
psql "postgresql://root@localhost:26257/defaultdb?sslmode=disable"
# Run queries to verify forwarding works
```

**Unit Tests:**
- Configuration loading and validation
- Connection pool management
- Message parsing and forwarding

**Integration Tests:**
- Connect through proxy to CRDB
- Execute SQL queries
- Verify results match direct connection
- Test connection pooling under load

**Deliverable:** Working non-attested proxy that forwards SQL traffic

**Success Criteria:**
- Clients can connect through proxy to CRDB
- SQL queries execute correctly
- No message corruption in forwarding
- Connection pooling reduces backend connections

---

### 1.3 AMD SEV-SNP Attestation Library

**Objective:** Create Go bindings for AMD SEV-SNP attestation via `/dev/sev-guest`

**File:** `pkg/attestation/types.go`
```go
package attestation

// SNP_GUEST_REQUEST ioctl structure
type SnpGuestRequest struct {
    ReqData   uint64 // Physical address of request
    RespData  uint64 // Physical address of response
    ExitInfo2 uint64 // Error code
}

// SNP Attestation Report (672 bytes)
type AttestationReport struct {
    Version         uint32
    GuestSVN        uint32
    Policy          uint64
    FamilyID        [16]byte
    ImageID         [16]byte
    VMPL            uint32
    SignatureAlgo   uint32
    PlatformVersion uint64
    PlatformInfo    uint64
    Flags           uint32
    Reserved        uint32
    ReportData      [64]byte  // User-provided nonce goes here
    Measurement     [48]byte  // SHA-384 of VM firmware/kernel/app
    HostData        [32]byte
    IDKeyDigest     [48]byte
    AuthorKeyDigest [48]byte
    ReportID        [32]byte
    ReportIDMA      [32]byte
    ReportedTCB     uint64
    Reserved2       [24]byte
    ChipID          [64]byte
    Reserved3       [192]byte
    Signature       [512]byte // ECDSA P-384 signature
}

type AttestationEvidence struct {
    Report      *AttestationReport
    Certificates [][]byte // VCEK + ASK + ARK certificates
    Nonce       []byte
    Timestamp   int64
}
```

**File:** `pkg/attestation/sev_snp.go`
```go
package attestation

/*
#cgo LDFLAGS: -lcrypto
#include <stdint.h>
#include <sys/ioctl.h>

// SEV-SNP ioctl commands
#define SNP_GET_REPORT _IOWR(0x53, 0x01, struct snp_guest_request_ioctl)

struct snp_guest_request_ioctl {
    uint64_t req_data;
    uint64_t resp_data;
    uint64_t exit_info2;
};

int get_attestation_report(int fd, void* req, void* resp);
*/
import "C"

import (
    "crypto/rand"
    "fmt"
    "os"
    "syscall"
    "unsafe"
)

const (
    SEV_GUEST_DEVICE = "/dev/sev-guest"
    REPORT_SIZE      = 672
)

type Attester struct {
    deviceFd int
}

func NewAttester() (*Attester, error) {
    fd, err := syscall.Open(SEV_GUEST_DEVICE, syscall.O_RDWR, 0)
    if err != nil {
        return nil, fmt.Errorf("failed to open %s: %w", SEV_GUEST_DEVICE, err)
    }
    return &Attester{deviceFd: fd}, nil
}

func (a *Attester) Close() error {
    return syscall.Close(a.deviceFd)
}

// GetReport fetches an attestation report with the given nonce
func (a *Attester) GetReport(nonce []byte) (*AttestationEvidence, error) {
    if len(nonce) > 64 {
        return nil, fmt.Errorf("nonce too large (max 64 bytes)")
    }

    // Prepare request
    var reportData [64]byte
    copy(reportData[:], nonce)

    // Allocate response buffer
    reportBuf := make([]byte, REPORT_SIZE)

    // Call ioctl
    req := C.struct_snp_guest_request_ioctl{
        req_data:   C.uint64_t(uintptr(unsafe.Pointer(&reportData[0]))),
        resp_data:  C.uint64_t(uintptr(unsafe.Pointer(&reportBuf[0]))),
        exit_info2: 0,
    }

    ret := C.get_attestation_report(C.int(a.deviceFd),
        unsafe.Pointer(&req), unsafe.Pointer(&reportBuf[0]))
    if ret != 0 {
        return nil, fmt.Errorf("ioctl failed: %d, exit_info2: %x", ret, req.exit_info2)
    }

    // Parse report
    report, err := parseReport(reportBuf)
    if err != nil {
        return nil, err
    }

    return &AttestationEvidence{
        Report:    report,
        Nonce:     nonce,
        Timestamp: time.Now().Unix(),
    }, nil
}

// GetExtendedReport includes VCEK certificate chain
func (a *Attester) GetExtendedReport(nonce []byte) (*AttestationEvidence, error) {
    evidence, err := a.GetReport(nonce)
    if err != nil {
        return nil, err
    }

    // Fetch certificates from AMD KDS (Key Distribution Service)
    certs, err := a.fetchCertificates(evidence.Report.ChipID)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch certificates: %w", err)
    }

    evidence.Certificates = certs
    return evidence, nil
}

// GenerateNonce creates a cryptographically random nonce
func GenerateNonce() ([]byte, error) {
    nonce := make([]byte, 32)
    _, err := rand.Read(nonce)
    return nonce, err
}

func parseReport(data []byte) (*AttestationReport, error) {
    if len(data) < REPORT_SIZE {
        return nil, fmt.Errorf("invalid report size: %d", len(data))
    }

    // Parse binary structure (use encoding/binary for proper field extraction)
    report := &AttestationReport{}
    // ... binary parsing logic ...
    return report, nil
}

func (a *Attester) fetchCertificates(chipID [64]byte) ([][]byte, error) {
    // Fetch from AMD KDS: https://kdsintf.amd.com/vcek/v1/{product}/{hwid}
    // Download VCEK, ASK, ARK certificates
    // Return as DER-encoded certificate chain
}
```

**File:** `pkg/attestation/sev_snp.c`
```c
#include <sys/ioctl.h>
#include <stdint.h>

#define SNP_GET_REPORT _IOWR(0x53, 0x01, struct snp_guest_request_ioctl)

struct snp_guest_request_ioctl {
    uint64_t req_data;
    uint64_t resp_data;
    uint64_t exit_info2;
};

int get_attestation_report(int fd, void* req, void* resp) {
    struct snp_guest_request_ioctl* ioctl_req = (struct snp_guest_request_ioctl*)req;
    return ioctl(fd, SNP_GET_REPORT, ioctl_req);
}
```

**Tasks:**
- [ ] Implement CGo wrapper for `/dev/sev-guest` ioctl
- [ ] Implement `GetReport()` - basic attestation report
- [ ] Implement `GetExtendedReport()` - with certificate chain
- [ ] Implement nonce generation (cryptographically secure)
- [ ] Parse `AttestationReport` binary structure
- [ ] Fetch VCEK/ASK/ARK certificates from AMD KDS
- [ ] Extract and expose measurement fields
- [ ] Handle error codes from SEV-SNP firmware

**Testing Strategy:**

**Mock for Unit Tests:**
```go
// pkg/attestation/mock.go
type MockAttester struct {
    reports map[string]*AttestationEvidence
}

func (m *MockAttester) GetReport(nonce []byte) (*AttestationEvidence, error) {
    // Return pre-generated mock report
}
```

**Integration Test (Requires SEV-SNP VM):**
```go
func TestRealAttestation(t *testing.T) {
    if os.Getenv("SEV_SNP_AVAILABLE") != "1" {
        t.Skip("SEV-SNP not available")
    }

    attester, err := NewAttester()
    require.NoError(t, err)
    defer attester.Close()

    nonce, _ := GenerateNonce()
    evidence, err := attester.GetReport(nonce)
    require.NoError(t, err)

    // Verify nonce is in report
    assert.Equal(t, nonce, evidence.Report.ReportData[:len(nonce)])
}
```

**Deliverable:** Go library that can fetch SEV-SNP attestation reports

**Success Criteria:**
- Can open `/dev/sev-guest` device
- Can generate cryptographically secure nonces
- Can fetch attestation reports with custom nonce
- Reports include valid measurements
- Certificate chain fetched from AMD KDS
- Mock implementation available for testing

---

## Phase 2: TLS 1.3 Exported Authenticators (2-3 weeks)

### 2.1 Implement RFC 9261 (Exported Authenticators)

**Objective:** Implement TLS Exported Authenticators outside Go stdlib using `ExportKeyingMaterial`

**Background:** Go's `crypto/tls` does not natively support RFC 9261, but provides the primitives needed via `ConnectionState.ExportKeyingMaterial()`.

**File:** `pkg/tls/exported_auth.go`
```go
package tls

import (
    "crypto"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "fmt"
)

// RFC 9261 Constants
const (
    // Exporter labels
    ExporterLabelAuthenticatorRequest = "EXPORTER-authenticator request"
    ExporterLabelAuthenticator        = "EXPORTER-authenticator"

    // Handshake message types
    HandshakeMsgCertificateRequest    = 13
    HandshakeMsgCertificate          = 11
    HandshakeMsgCertificateVerify    = 15
)

// AuthenticatorRequest is sent by the requesting party
type AuthenticatorRequest struct {
    CertificateRequestContext []byte
    Extensions                []Extension
}

// Authenticator is the response containing proof of identity
type Authenticator struct {
    CertificateRequestContext []byte
    Certificate               *x509.Certificate
    CertificateVerify         []byte
    Extensions                []Extension
}

type Extension struct {
    Type uint16
    Data []byte
}

// GenerateAuthenticatorRequest creates an authenticator request
func GenerateAuthenticatorRequest(conn *tls.Conn, extensions []Extension) (*AuthenticatorRequest, error) {
    // Generate random certificate_request_context (32 bytes)
    context := make([]byte, 32)
    if _, err := rand.Read(context); err != nil {
        return nil, err
    }

    return &AuthenticatorRequest{
        CertificateRequestContext: context,
        Extensions:                extensions,
    }, nil
}

// GenerateAuthenticator creates an authenticator in response to a request
func GenerateAuthenticator(
    conn *tls.Conn,
    request *AuthenticatorRequest,
    cert *x509.Certificate,
    privateKey crypto.PrivateKey,
    attestationEvidence []byte,
) ([]byte, error) {

    // 1. Create Certificate message
    certMsg := encodeCertificateMessage(request.CertificateRequestContext, cert, attestationEvidence)

    // 2. Compute Finished MAC using exported keying material
    handshakeContext := buildHandshakeContext(request, certMsg)

    // Export keying material for authenticator
    exportedKey, err := conn.ConnectionState().ExportKeyingMaterial(
        ExporterLabelAuthenticator,
        handshakeContext,
        32, // Key length
    )
    if err != nil {
        return nil, fmt.Errorf("failed to export keying material: %w", err)
    }

    // 3. Create CertificateVerify message
    signatureInput := buildCertificateVerifyInput(handshakeContext, exportedKey)
    signature, err := signMessage(privateKey, signatureInput)
    if err != nil {
        return nil, err
    }

    certVerifyMsg := encodeCertificateVerify(signature)

    // 4. Combine into Authenticator
    authenticator := encodeAuthenticator(
        request.CertificateRequestContext,
        certMsg,
        certVerifyMsg,
    )

    return authenticator, nil
}

// VerifyAuthenticator verifies an authenticator received from peer
func VerifyAuthenticator(
    conn *tls.Conn,
    request *AuthenticatorRequest,
    authenticatorData []byte,
) (*Authenticator, error) {

    // 1. Parse authenticator
    auth, err := parseAuthenticator(authenticatorData)
    if err != nil {
        return nil, err
    }

    // 2. Verify certificate_request_context matches
    if !bytes.Equal(auth.CertificateRequestContext, request.CertificateRequestContext) {
        return nil, fmt.Errorf("context mismatch")
    }

    // 3. Export keying material
    handshakeContext := buildHandshakeContext(request, encodeCertificateMessage(...))
    exportedKey, err := conn.ConnectionState().ExportKeyingMaterial(
        ExporterLabelAuthenticator,
        handshakeContext,
        32,
    )
    if err != nil {
        return nil, err
    }

    // 4. Verify signature in CertificateVerify
    signatureInput := buildCertificateVerifyInput(handshakeContext, exportedKey)
    if err := verifyCertificateSignature(auth.Certificate, signatureInput, auth.CertificateVerify); err != nil {
        return nil, fmt.Errorf("signature verification failed: %w", err)
    }

    return auth, nil
}

// Helper functions for message encoding/decoding (TLS wire format)

func encodeCertificateMessage(context []byte, cert *x509.Certificate, extensions []byte) []byte {
    // TLS 1.3 Certificate message format:
    // - certificate_request_context length (1 byte)
    // - certificate_request_context
    // - certificate_list length (3 bytes)
    // - certificate_list:
    //   - cert_data length (3 bytes)
    //   - cert_data (DER)
    //   - extensions length (2 bytes)
    //   - extensions

    buf := make([]byte, 0, 4096)
    // ... TLS wire format encoding ...
    return buf
}

func buildHandshakeContext(request *AuthenticatorRequest, certMsg []byte) []byte {
    // Hash of:
    // - ClientHello..ServerFinished (from TLS handshake)
    // - CertificateRequest
    // - Certificate
}

func buildCertificateVerifyInput(handshakeContext, exportedKey []byte) []byte {
    // RFC 8446 Section 4.4.3:
    // - 64 spaces (0x20)
    // - "TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify"
    // - 0x00
    // - Hash(handshakeContext)
}
```

**Tasks:**
- [ ] Implement `GenerateAuthenticatorRequest()` with random context generation
- [ ] Implement `GenerateAuthenticator()` using `ExportKeyingMaterial()`
- [ ] Implement `VerifyAuthenticator()` with signature verification
- [ ] Implement TLS wire format encoding for Certificate message
- [ ] Implement TLS wire format encoding for CertificateVerify message
- [ ] Implement handshake context hashing per RFC 9261
- [ ] Handle signature algorithms (ECDSA P-384, RSA-PSS)
- [ ] Add support for custom extensions in authenticators

**Testing:**
```go
func TestExportedAuthenticators(t *testing.T) {
    // Create TLS connection
    serverCert, serverKey := generateTestCert()
    clientCert, clientKey := generateTestCert()

    // Simulate TLS handshake
    clientConn, serverConn := testTLSConnection(clientCert, serverCert)

    // Client requests authenticator from server
    request, err := GenerateAuthenticatorRequest(clientConn, nil)
    require.NoError(t, err)

    // Server generates authenticator
    attestation := []byte("mock attestation evidence")
    authenticator, err := GenerateAuthenticator(
        serverConn,
        request,
        serverCert,
        serverKey,
        attestation,
    )
    require.NoError(t, err)

    // Client verifies authenticator
    verified, err := VerifyAuthenticator(clientConn, request, authenticator)
    require.NoError(t, err)
    assert.NotNil(t, verified.Certificate)
}
```

**Deliverable:** RFC 9261 implementation working outside stdlib

**Success Criteria:**
- Can generate authenticator requests with unique contexts
- Can create authenticators bound to TLS session
- Can verify authenticators using exported keying material
- Signature verification passes with correct keys
- Integration with real TLS connections works

---

### 2.2 Embed Attestation in TLS Extension

**Objective:** Define custom X.509 certificate extension to carry EAT (Entity Attestation Token)

**File:** `pkg/tls/attestation_extension.go`
```go
package tls

import (
    "crypto/x509"
    "encoding/asn1"
    "fmt"
    "github.com/fxamacker/cbor/v2"
    "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/attestation"
)

// Custom OID for attestation extension
var (
    // Private enterprise number: 1.3.6.1.4.1.XXXXX.1.1
    OIDAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
)

// EntityAttestationToken follows EAT specification (RFC 8392)
type EntityAttestationToken struct {
    Nonce        []byte                         `cbor:"10,keyasint"` // EAT nonce claim
    Report       []byte                         `cbor:"-75000,keyasint"` // Custom: SEV-SNP report
    Measurements *AttestationMeasurements       `cbor:"-75001,keyasint"` // Custom
    TCBVersion   string                         `cbor:"-75002,keyasint"` // Custom
    Timestamp    int64                          `cbor:"1,keyasint"`  // EAT iat claim
    Issuer       string                         `cbor:"3,keyasint"`  // EAT iss claim
}

type AttestationMeasurements struct {
    Kernel      []byte `cbor:"kernel"`
    Application []byte `cbor:"application"`
}

// CreateAttestationExtension embeds attestation evidence in X.509 extension
func CreateAttestationExtension(evidence *attestation.AttestationEvidence) ([]byte, error) {
    // Create EAT
    eat := &EntityAttestationToken{
        Nonce:      evidence.Nonce,
        Report:     evidence.Report.Marshal(), // Serialize report
        Measurements: &AttestationMeasurements{
            Kernel:      evidence.Report.Measurement[:24],
            Application: evidence.Report.Measurement[24:],
        },
        TCBVersion: fmt.Sprintf("%d", evidence.Report.PlatformVersion),
        Timestamp:  evidence.Timestamp,
        Issuer:     "sev-snp-attester",
    }

    // Encode as CBOR
    cborData, err := cbor.Marshal(eat)
    if err != nil {
        return nil, fmt.Errorf("failed to encode EAT: %w", err)
    }

    return cborData, nil
}

// ExtractAttestationExtension extracts and parses attestation from certificate
func ExtractAttestationExtension(cert *x509.Certificate) (*EntityAttestationToken, error) {
    // Find extension by OID
    for _, ext := range cert.Extensions {
        if ext.Id.Equal(OIDAttestation) {
            // Decode CBOR
            var eat EntityAttestationToken
            if err := cbor.Unmarshal(ext.Value, &eat); err != nil {
                return nil, fmt.Errorf("failed to decode EAT: %w", err)
            }
            return &eat, nil
        }
    }
    return nil, fmt.Errorf("attestation extension not found")
}

// CreateCertificateWithAttestation creates a self-signed cert with attestation extension
func CreateCertificateWithAttestation(
    evidence *attestation.AttestationEvidence,
    privateKey crypto.PrivateKey,
) (*x509.Certificate, error) {

    // Create attestation extension
    extValue, err := CreateAttestationExtension(evidence)
    if err != nil {
        return nil, err
    }

    // Create certificate template
    template := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            CommonName:   "SEV-SNP Attested Proxy",
            Organization: []string{"Attested TLS Proxy"},
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(24 * time.Hour), // Short-lived
        KeyUsage:              x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        ExtraExtensions: []pkix.Extension{
            {
                Id:       OIDAttestation,
                Critical: false,
                Value:    extValue,
            },
        },
    }

    // Self-sign
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey(privateKey), privateKey)
    if err != nil {
        return nil, err
    }

    return x509.ParseCertificate(certDER)
}
```

**Tasks:**
- [ ] Define custom OID for attestation extension (register private enterprise number)
- [ ] Implement EAT structure following RFC 8392
- [ ] Encode attestation report as CBOR
- [ ] Create X.509 certificate with attestation extension
- [ ] Extract and parse attestation from peer certificate
- [ ] Handle certificate lifecycle (generation per connection)
- [ ] Support certificate caching (same attestation for multiple connections)

**Testing:**
```go
func TestAttestationExtension(t *testing.T) {
    // Generate mock attestation
    nonce, _ := attestation.GenerateNonce()
    evidence := &attestation.AttestationEvidence{
        Report:    mockReport(),
        Nonce:     nonce,
        Timestamp: time.Now().Unix(),
    }

    // Create cert with extension
    privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    cert, err := CreateCertificateWithAttestation(evidence, privateKey)
    require.NoError(t, err)

    // Extract extension
    eat, err := ExtractAttestationExtension(cert)
    require.NoError(t, err)

    // Verify nonce
    assert.Equal(t, nonce, eat.Nonce)
}
```

**Deliverable:** TLS extension mechanism for carrying attestation

**Success Criteria:**
- Can create certificates with attestation extension
- Extension contains valid CBOR-encoded EAT
- Can extract and parse attestation from certificates
- Extension survives TLS handshake
- Multiple connections can reuse same certificate

---

### 2.3 Policy Engine for Measurement Verification

**Objective:** Verify attestation reports against configured policies

**File:** `pkg/policy/policy.go`
```go
package policy

import (
    "crypto/sha512"
    "encoding/hex"
    "fmt"
    "time"
)

type Policy struct {
    Measurements    []MeasurementPolicy `yaml:"measurements"`
    TCBVersionMin   string              `yaml:"tcb_version_min"`
    NonceTTL        time.Duration       `yaml:"nonce_ttl"`
    AllowSimulated  bool                `yaml:"allow_simulated"` // For dev only
}

type MeasurementPolicy struct {
    Name string `yaml:"name"`   // "kernel", "application", etc.
    SHA384 string `yaml:"sha384"` // Expected hash
}

type VerificationResult struct {
    Allowed bool
    Reason  string
    Details map[string]interface{}
}
```

**File:** `pkg/policy/verifier.go`
```go
package policy

import (
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/asn1"
    "fmt"
    "time"
    "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/attestation"
    tlsext "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/tls"
)

type Verifier struct {
    policy    *Policy
    rootCerts *x509.CertPool // AMD root certificates
    nonceCache map[string]time.Time // Track used nonces
}

func NewVerifier(policy *Policy) (*Verifier, error) {
    // Load AMD root certificates (ARK)
    rootCerts, err := loadAMDRootCerts()
    if err != nil {
        return nil, err
    }

    return &Verifier{
        policy:     policy,
        rootCerts:  rootCerts,
        nonceCache: make(map[string]time.Time),
    }, nil
}

// VerifyAttestation performs full attestation verification
func (v *Verifier) VerifyAttestation(eat *tlsext.EntityAttestationToken) (*VerificationResult, error) {
    result := &VerificationResult{
        Allowed: false,
        Details: make(map[string]interface{}),
    }

    // 1. Parse attestation report
    report, err := attestation.ParseReport(eat.Report)
    if err != nil {
        result.Reason = fmt.Sprintf("invalid report: %v", err)
        return result, nil
    }

    // 2. Verify nonce freshness
    if err := v.verifyNonce(eat.Nonce, eat.Timestamp); err != nil {
        result.Reason = fmt.Sprintf("nonce verification failed: %v", err)
        return result, nil
    }

    // 3. Verify signature chain (Report → VCEK → ASK → ARK)
    if err := v.verifySignatureChain(report, eat.Certificates); err != nil {
        result.Reason = fmt.Sprintf("signature chain invalid: %v", err)
        return result, nil
    }

    // 4. Verify measurements against policy
    if err := v.verifyMeasurements(report.Measurement, eat.Measurements); err != nil {
        result.Reason = fmt.Sprintf("measurement mismatch: %v", err)
        result.Details["expected"] = v.policy.Measurements
        result.Details["actual"] = eat.Measurements
        return result, nil
    }

    // 5. Verify TCB version
    if err := v.verifyTCBVersion(eat.TCBVersion); err != nil {
        result.Reason = fmt.Sprintf("TCB version too old: %v", err)
        return result, nil
    }

    // 6. Check guest policy
    if err := v.verifyGuestPolicy(report.Policy); err != nil {
        result.Reason = fmt.Sprintf("guest policy violation: %v", err)
        return result, nil
    }

    result.Allowed = true
    result.Reason = "attestation verified"
    return result, nil
}

func (v *Verifier) verifyNonce(nonce []byte, timestamp int64) error {
    nonceKey := hex.EncodeToString(nonce)

    // Check if nonce was already used
    if usedAt, exists := v.nonceCache[nonceKey]; exists {
        return fmt.Errorf("nonce replay detected (used at %v)", usedAt)
    }

    // Check timestamp freshness
    age := time.Now().Unix() - timestamp
    if age > int64(v.policy.NonceTTL.Seconds()) {
        return fmt.Errorf("nonce expired (age: %ds, max: %ds)", age, int64(v.policy.NonceTTL.Seconds()))
    }

    // Mark nonce as used
    v.nonceCache[nonceKey] = time.Now()

    // Cleanup old nonces (prevent memory leak)
    v.cleanupNonceCache()

    return nil
}

func (v *Verifier) verifySignatureChain(report *attestation.AttestationReport, certChain [][]byte) error {
    // AMD SEV-SNP signature chain:
    // 1. Report is signed by VCEK (Versioned Chip Endorsement Key)
    // 2. VCEK is signed by ASK (AMD SEV Signing Key)
    // 3. ASK is signed by ARK (AMD Root Key)
    // 4. ARK is self-signed (trust anchor)

    if len(certChain) < 3 {
        return fmt.Errorf("incomplete certificate chain (need VCEK, ASK, ARK)")
    }

    // Parse certificates
    vcek, err := x509.ParseCertificate(certChain[0])
    if err != nil {
        return fmt.Errorf("invalid VCEK: %w", err)
    }

    ask, err := x509.ParseCertificate(certChain[1])
    if err != nil {
        return fmt.Errorf("invalid ASK: %w", err)
    }

    ark, err := x509.ParseCertificate(certChain[2])
    if err != nil {
        return fmt.Errorf("invalid ARK: %w", err)
    }

    // Verify ARK is in trusted roots
    if !v.rootCerts.Contains(ark) {
        return fmt.Errorf("untrusted ARK")
    }

    // Verify ASK is signed by ARK
    if err := ask.CheckSignatureFrom(ark); err != nil {
        return fmt.Errorf("ASK signature verification failed: %w", err)
    }

    // Verify VCEK is signed by ASK
    if err := vcek.CheckSignatureFrom(ask); err != nil {
        return fmt.Errorf("VCEK signature verification failed: %w", err)
    }

    // Verify report signature using VCEK public key
    if err := verifyReportSignature(report, vcek.PublicKey.(*ecdsa.PublicKey)); err != nil {
        return fmt.Errorf("report signature verification failed: %w", err)
    }

    return nil
}

func verifyReportSignature(report *attestation.AttestationReport, vcekPubKey *ecdsa.PublicKey) error {
    // SEV-SNP report signature is ECDSA P-384 over SHA-384 of report bytes (excluding signature)
    reportBytes := report.Marshal()[:len(reportBytes)-512] // Exclude 512-byte signature

    hash := sha512.Sum384(reportBytes)

    // Parse signature (R || S format, 48 bytes each)
    r := new(big.Int).SetBytes(report.Signature[:48])
    s := new(big.Int).SetBytes(report.Signature[48:96])

    if !ecdsa.Verify(vcekPubKey, hash[:], r, s) {
        return fmt.Errorf("ECDSA signature verification failed")
    }

    return nil
}

func (v *Verifier) verifyMeasurements(reportMeasurement [48]byte, eat *tlsext.AttestationMeasurements) error {
    // Compare against policy
    for _, expected := range v.policy.Measurements {
        expectedBytes, err := hex.DecodeString(expected.SHA384)
        if err != nil {
            return fmt.Errorf("invalid expected measurement %s: %w", expected.Name, err)
        }

        var actual []byte
        switch expected.Name {
        case "kernel":
            actual = eat.Kernel
        case "application":
            actual = eat.Application
        default:
            return fmt.Errorf("unknown measurement type: %s", expected.Name)
        }

        if !bytes.Equal(expectedBytes, actual) {
            return fmt.Errorf("%s measurement mismatch", expected.Name)
        }
    }

    return nil
}

func (v *Verifier) verifyTCBVersion(version string) error {
    // Parse and compare versions
    if version < v.policy.TCBVersionMin {
        return fmt.Errorf("TCB version %s < minimum %s", version, v.policy.TCBVersionMin)
    }
    return nil
}

func (v *Verifier) verifyGuestPolicy(policy uint64) error {
    // Check SEV-SNP guest policy bits
    // Bit 0: SMT disabled
    // Bit 1-15: ABI minor version
    // Bit 16-31: ABI major version
    // Bit 32-47: SMT protection enabled
    // etc.

    // Example: Require SMT disabled for security
    if policy&0x01 == 0 {
        return fmt.Errorf("SMT not disabled (policy: %x)", policy)
    }

    return nil
}

func (v *Verifier) cleanupNonceCache() {
    // Remove nonces older than 2x TTL
    cutoff := time.Now().Add(-2 * v.policy.NonceTTL)
    for nonce, usedAt := range v.nonceCache {
        if usedAt.Before(cutoff) {
            delete(v.nonceCache, nonce)
        }
    }
}

func loadAMDRootCerts() (*x509.CertPool, error) {
    // Load AMD ARK (hardcoded or from file)
    pool := x509.NewCertPool()

    // AMD Milan ARK certificate (PEM format)
    arkPEM := `-----BEGIN CERTIFICATE-----
    MII... (AMD ARK certificate)
    -----END CERTIFICATE-----`

    if !pool.AppendCertsFromPEM([]byte(arkPEM)) {
        return nil, fmt.Errorf("failed to load AMD ARK")
    }

    return pool, nil
}
```

**Configuration:** `config/policy.yaml`
```yaml
measurements:
  - name: "kernel"
    sha384: "a1b2c3d4e5f6..." # SHA-384 of kernel
  - name: "application"
    sha384: "f6e5d4c3b2a1..." # SHA-384 of proxy binary

tcb_version_min: "1.51"
nonce_ttl: 300s # 5 minutes
allow_simulated: false # Never true in production
```

**Tasks:**
- [ ] Implement policy loading from YAML
- [ ] Verify SEV-SNP signature chain (VCEK → ASK → ARK)
- [ ] Verify report signature using VCEK public key (ECDSA P-384)
- [ ] Compare measurements against expected values
- [ ] Verify TCB version >= minimum
- [ ] Verify nonce freshness and prevent replay
- [ ] Check guest policy bits (SMT, debug mode, etc.)
- [ ] Add nonce cache with TTL-based cleanup
- [ ] Load AMD root certificates (ARK)

**Testing:**
```go
func TestPolicyVerification(t *testing.T) {
    policy := &Policy{
        Measurements: []MeasurementPolicy{
            {Name: "kernel", SHA384: "abcd..."},
            {Name: "application", SHA384: "1234..."},
        },
        TCBVersionMin: "1.51",
        NonceTTL:      5 * time.Minute,
    }

    verifier, err := NewVerifier(policy)
    require.NoError(t, err)

    // Valid attestation
    eat := mockValidEAT()
    result, err := verifier.VerifyAttestation(eat)
    require.NoError(t, err)
    assert.True(t, result.Allowed)

    // Invalid measurement
    eat.Measurements.Kernel = []byte("wrong")
    result, err = verifier.VerifyAttestation(eat)
    require.NoError(t, err)
    assert.False(t, result.Allowed)
    assert.Contains(t, result.Reason, "measurement mismatch")

    // Replay attack
    result, _ = verifier.VerifyAttestation(mockValidEAT()) // Same nonce
    assert.False(t, result.Allowed)
    assert.Contains(t, result.Reason, "replay")
}
```

**Deliverable:** Policy-based attestation verifier with signature chain validation

**Success Criteria:**
- Can verify AMD SEV-SNP signature chains
- Detects measurement mismatches
- Prevents nonce replay attacks
- Enforces TCB version minimums
- Configurable via YAML
- Comprehensive error reporting

---

## Phase 3: OAuth Token Exchange & HBA Integration (2-3 weeks)

### 3.1 Security Token Service (STS) Client

**Objective:** Implement OAuth 2.0 Token Exchange (RFC 8693) with attestation evidence

**File:** `pkg/auth/sts_client.go`
```go
package auth

import (
    "bytes"
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "time"
)

const (
    GrantTypeTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
    TokenTypeAttestation       = "urn:ietf:params:oauth:token-type:attestation"
    TokenTypeJWT               = "urn:ietf:params:oauth:token-type:jwt"
)

type STSClient struct {
    endpoint   string
    httpClient *http.Client
    tokenCache map[string]*CachedToken
}

type CachedToken struct {
    Token     string
    ExpiresAt time.Time
}

type TokenResponse struct {
    AccessToken     string `json:"access_token"`
    TokenType       string `json:"token_type"`
    ExpiresIn       int    `json:"expires_in"`
    Scope           string `json:"scope,omitempty"`
    IssuedTokenType string `json:"issued_token_type"`
}

func NewSTSClient(endpoint string) *STSClient {
    return &STSClient{
        endpoint: endpoint,
        httpClient: &http.Client{
            Timeout: 10 * time.Second,
        },
        tokenCache: make(map[string]*CachedToken),
    }
}

// ExchangeAttestation exchanges attestation evidence for a JWT token
func (s *STSClient) ExchangeAttestation(
    attestationEvidence []byte,
    scope string,
    dpopKey crypto.PrivateKey, // For DPoP binding
) (*TokenResponse, error) {

    // Check cache first
    cacheKey := sha256.Sum256(attestationEvidence)
    if cached, ok := s.tokenCache[string(cacheKey[:])]; ok {
        if time.Now().Before(cached.ExpiresAt) {
            return &TokenResponse{
                AccessToken: cached.Token,
                TokenType:   "DPoP",
            }, nil
        }
        delete(s.tokenCache, string(cacheKey[:]))
    }

    // Prepare request
    data := url.Values{}
    data.Set("grant_type", GrantTypeTokenExchange)
    data.Set("subject_token", base64.StdEncoding.EncodeToString(attestationEvidence))
    data.Set("subject_token_type", TokenTypeAttestation)
    data.Set("requested_token_type", TokenTypeJWT)
    if scope != "" {
        data.Set("scope", scope)
    }

    req, err := http.NewRequest("POST", s.endpoint, bytes.NewBufferString(data.Encode()))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    // Add DPoP header (RFC 9449)
    if dpopKey != nil {
        dpopProof, err := generateDPoPProof(dpopKey, "POST", s.endpoint, nil)
        if err != nil {
            return nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
        }
        req.Header.Set("DPoP", dpopProof)
    }

    // Send request
    resp, err := s.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("STS request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("STS error %d: %s", resp.StatusCode, body)
    }

    // Parse response
    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return nil, fmt.Errorf("failed to parse token response: %w", err)
    }

    // Cache token
    expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
    s.tokenCache[string(cacheKey[:])] = &CachedToken{
        Token:     tokenResp.AccessToken,
        ExpiresAt: expiresAt,
    }

    return &tokenResp, nil
}

// generateDPoPProof creates a DPoP (Demonstrating Proof-of-Possession) JWT
func generateDPoPProof(privateKey crypto.PrivateKey, method, url string, accessToken *string) (string, error) {
    // DPoP JWT header
    header := map[string]interface{}{
        "typ": "dpop+jwt",
        "alg": "ES384", // ECDSA P-384
        "jwk": extractJWK(privateKey),
    }

    // DPoP JWT claims
    now := time.Now().Unix()
    claims := map[string]interface{}{
        "jti": generateJTI(),
        "htm": method,
        "htu": url,
        "iat": now,
    }

    // Add access token hash if provided
    if accessToken != nil {
        hash := sha256.Sum256([]byte(*accessToken))
        claims["ath"] = base64.RawURLEncoding.EncodeToString(hash[:])
    }

    // Sign JWT
    return signJWT(header, claims, privateKey)
}

func generateJTI() string {
    b := make([]byte, 16)
    rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)
}

func extractJWK(privateKey crypto.PrivateKey) map[string]interface{} {
    // Extract public key and format as JWK (JSON Web Key)
    // For ECDSA P-384: {"kty":"EC","crv":"P-384","x":"...","y":"..."}
}

func signJWT(header, claims map[string]interface{}, privateKey crypto.PrivateKey) (string, error) {
    // Encode header and claims as base64url
    // Sign with private key
    // Return header.claims.signature
}
```

**Tasks:**
- [ ] Implement OAuth Token Exchange request (RFC 8693)
- [ ] Implement DPoP JWT generation (RFC 9449)
- [ ] Add token caching with TTL
- [ ] Handle STS errors gracefully
- [ ] Support automatic token refresh
- [ ] Add metrics for token exchange success/failure

**Testing:**
```go
func TestSTSTokenExchange(t *testing.T) {
    // Mock STS server
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "POST", r.Method)
        assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

        // Parse request
        r.ParseForm()
        assert.Equal(t, GrantTypeTokenExchange, r.FormValue("grant_type"))
        assert.Equal(t, TokenTypeAttestation, r.FormValue("subject_token_type"))

        // Return token
        json.NewEncoder(w).Encode(TokenResponse{
            AccessToken:     "eyJhbGciOi...",
            TokenType:       "Bearer",
            ExpiresIn:       3600,
            IssuedTokenType: TokenTypeJWT,
        })
    }))
    defer server.Close()

    // Test exchange
    client := NewSTSClient(server.URL)
    dpopKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

    resp, err := client.ExchangeAttestation([]byte("mock attestation"), "db:read", dpopKey)
    require.NoError(t, err)
    assert.NotEmpty(t, resp.AccessToken)

    // Test caching
    resp2, _ := client.ExchangeAttestation([]byte("mock attestation"), "db:read", dpopKey)
    assert.Equal(t, resp.AccessToken, resp2.AccessToken) // Should be cached
}
```

**Deliverable:** STS client with DPoP support

---

### 3.2 CockroachDB HBA Configuration

**Objective:** Configure CockroachDB to only accept connections from the proxy

**HBA Configuration File:** `hba.conf` (deployed on CRDB nodes)
```
# TYPE  DATABASE  USER          ADDRESS         METHOD        OPTIONS

# Allow proxy with certificate authentication
hostssl all       all           10.0.1.5/32     cert-password map=proxy_user

# Reject all other connections
hostssl all       all           0.0.0.0/0       reject

# Local connections for admin (emergencies)
local   all       root                          trust
```

**Certificate-based Authentication:**
- Proxy connects using client certificate
- Certificate CN mapped to CRDB user via `ident map`

**Ident Map:** `pg_ident.conf`
```
# MAPNAME      SYSTEM-USERNAME          PG-USERNAME
proxy_user     proxy-service-account    proxy_user
```

**CRDB Setup Script:** `scripts/setup_crdb_hba.sh`
```bash
#!/bin/bash
set -e

CRDB_HOST=${1:-localhost:26258}
CERTS_DIR=./certs

# Create proxy service account in CRDB
cockroach sql --host=$CRDB_HOST --certs-dir=$CERTS_DIR <<EOF
CREATE USER IF NOT EXISTS proxy_user WITH PASSWORD NULL;
GRANT ALL ON DATABASE defaultdb TO proxy_user;
GRANT ADMIN TO proxy_user; -- For full access (adjust per security policy)
EOF

# Deploy HBA configuration
cat > /tmp/hba.conf <<EOF
hostssl all all 10.0.1.5/32 cert-password map=proxy_user
hostssl all all 0.0.0.0/0   reject
local   all root            trust
EOF

# Apply HBA (method depends on CRDB deployment)
# For single-node:
cockroach sql --host=$CRDB_HOST --certs-dir=$CERTS_DIR --execute="
SET CLUSTER SETTING server.host_based_authentication.configuration = '$(cat /tmp/hba.conf)'
"

echo "HBA configured. Only proxy can connect."
```

**Tasks:**
- [ ] Create HBA configuration file
- [ ] Create proxy service account in CRDB
- [ ] Generate client certificate for proxy
- [ ] Configure CRDB to enforce HBA
- [ ] Test direct client connection (should be rejected)
- [ ] Test proxy connection (should succeed)
- [ ] Document emergency access procedures

**Testing:**
```bash
# Should FAIL (direct client connection)
psql "postgresql://root@crdb-host:26257/defaultdb?sslmode=verify-full"

# Should SUCCEED (connection through proxy)
psql "postgresql://root@proxy-host:26257/defaultdb?sslmode=require"
```

**Deliverable:** CRDB configured to only accept proxy connections

---

### 3.3 End-to-End Authentication Flow

**Objective:** Integrate attestation, token exchange, and HBA into request flow

**File:** `pkg/auth/authenticator.go`
```go
package auth

import (
    "crypto"
    "fmt"
    "github.com/jackc/pgproto3/v2"
    "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/attestation"
    "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/policy"
    tlsext "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/tls"
)

type Authenticator struct {
    verifier     *policy.Verifier
    stsClient    *STSClient
    dpopKey      crypto.PrivateKey
    userMapping  map[string]string // JWT claims → CRDB user
    auditLog     *AuditLogger
}

type AuthResult struct {
    Allowed        bool
    CRDBUser       string
    CRDBPassword   string
    Reason         string
    AuditMetadata  map[string]interface{}
}

func NewAuthenticator(
    verifier *policy.Verifier,
    stsClient *STSClient,
    dpopKey crypto.PrivateKey,
) *Authenticator {
    return &Authenticator{
        verifier:    verifier,
        stsClient:   stsClient,
        dpopKey:     dpopKey,
        userMapping: make(map[string]string),
        auditLog:    NewAuditLogger(),
    }
}

// AuthenticateRequest processes client authentication with attestation
func (a *Authenticator) AuthenticateRequest(
    clientCert *x509.Certificate,
    startupMsg *pgproto3.StartupMessage,
) (*AuthResult, error) {

    result := &AuthResult{
        Allowed:       false,
        AuditMetadata: make(map[string]interface{}),
    }

    // 1. Extract attestation from client certificate
    eat, err := tlsext.ExtractAttestationExtension(clientCert)
    if err != nil {
        result.Reason = fmt.Sprintf("no attestation in certificate: %v", err)
        a.auditLog.LogAuthFailure(result)
        return result, nil
    }

    result.AuditMetadata["nonce"] = hex.EncodeToString(eat.Nonce)
    result.AuditMetadata["timestamp"] = eat.Timestamp

    // 2. Verify attestation against policy
    verifyResult, err := a.verifier.VerifyAttestation(eat)
    if err != nil {
        result.Reason = fmt.Sprintf("verification error: %v", err)
        a.auditLog.LogAuthFailure(result)
        return result, nil
    }

    if !verifyResult.Allowed {
        result.Reason = verifyResult.Reason
        result.AuditMetadata["verification_details"] = verifyResult.Details
        a.auditLog.LogAuthFailure(result)
        return result, nil
    }

    // 3. Exchange attestation for JWT token
    attestationBytes, _ := cbor.Marshal(eat)
    tokenResp, err := a.stsClient.ExchangeAttestation(
        attestationBytes,
        "database:access",
        a.dpopKey,
    )
    if err != nil {
        result.Reason = fmt.Sprintf("token exchange failed: %v", err)
        a.auditLog.LogAuthFailure(result)
        return result, nil
    }

    result.AuditMetadata["token_type"] = tokenResp.TokenType

    // 4. Parse JWT and map to CRDB user
    claims, err := parseJWT(tokenResp.AccessToken)
    if err != nil {
        result.Reason = fmt.Sprintf("invalid JWT: %v", err)
        a.auditLog.LogAuthFailure(result)
        return result, nil
    }

    crdbUser, err := a.mapUserFromClaims(claims)
    if err != nil {
        result.Reason = fmt.Sprintf("user mapping failed: %v", err)
        a.auditLog.LogAuthFailure(result)
        return result, nil
    }

    // 5. Success
    result.Allowed = true
    result.CRDBUser = crdbUser
    result.CRDBPassword = "" // Using cert auth for proxy→CRDB
    result.Reason = "authentication successful"
    result.AuditMetadata["crdb_user"] = crdbUser
    result.AuditMetadata["client_requested_user"] = startupMsg.Parameters["user"]

    a.auditLog.LogAuthSuccess(result)
    return result, nil
}

func (a *Authenticator) mapUserFromClaims(claims map[string]interface{}) (string, error) {
    // Extract user identifier from JWT claims
    // Example: email claim → CRDB user
    email, ok := claims["email"].(string)
    if !ok {
        return "", fmt.Errorf("no email claim in JWT")
    }

    // Simple mapping (could be database lookup in production)
    if crdbUser, ok := a.userMapping[email]; ok {
        return crdbUser, nil
    }

    // Default: use email prefix as username
    return strings.Split(email, "@")[0], nil
}

func parseJWT(token string) (map[string]interface{}, error) {
    // Parse and validate JWT (skip signature verification if STS is trusted)
    // In production: verify signature using STS public key
}
```

**Audit Logger:** `pkg/auth/audit.go`
```go
package auth

import (
    "encoding/json"
    "os"
    "time"
)

type AuditLogger struct {
    file *os.File
}

type AuditEvent struct {
    Timestamp time.Time              `json:"timestamp"`
    Event     string                 `json:"event"`
    Result    string                 `json:"result"`
    Details   map[string]interface{} `json:"details"`
}

func NewAuditLogger() *AuditLogger {
    file, _ := os.OpenFile("/var/log/proxy-audit.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
    return &AuditLogger{file: file}
}

func (a *AuditLogger) LogAuthSuccess(result *AuthResult) {
    event := AuditEvent{
        Timestamp: time.Now(),
        Event:     "authentication",
        Result:    "success",
        Details:   result.AuditMetadata,
    }
    json.NewEncoder(a.file).Encode(event)
}

func (a *AuditLogger) LogAuthFailure(result *AuthResult) {
    event := AuditEvent{
        Timestamp: time.Now(),
        Event:     "authentication",
        Result:    "failure",
        Details: map[string]interface{}{
            "reason":   result.Reason,
            "metadata": result.AuditMetadata,
        },
    }
    json.NewEncoder(a.file).Encode(event)
}
```

**Integration into Proxy:** `pkg/backend/cockroach.go` (updated)
```go
func (p *Proxy) handleConnection(clientConn *tls.Conn) {
    // 1. Get client certificate
    clientCert := clientConn.ConnectionState().PeerCertificates[0]

    // 2. Read PostgreSQL startup message
    frontend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)
    startupMsg, err := frontend.ReceiveStartupMessage()
    if err != nil {
        log.Error("failed to read startup message", err)
        return
    }

    // 3. Authenticate with attestation
    authResult, err := p.authenticator.AuthenticateRequest(clientCert, startupMsg)
    if err != nil || !authResult.Allowed {
        // Send authentication error to client
        frontend.Send(&pgproto3.ErrorResponse{
            Severity: "FATAL",
            Code:     "28000", // invalid_authorization_specification
            Message:  authResult.Reason,
        })
        return
    }

    // 4. Connect to CRDB as authenticated user
    backendConn, err := p.backend.ConnectAs(authResult.CRDBUser, authResult.CRDBPassword)
    if err != nil {
        log.Error("failed to connect to CRDB", err)
        return
    }

    // 5. Forward traffic
    go p.forwardClientToBackend(clientConn, backendConn)
    go p.forwardBackendToClient(backendConn, clientConn)
}
```

**Tasks:**
- [ ] Implement attestation extraction from client cert
- [ ] Integrate policy verification
- [ ] Implement token exchange flow
- [ ] Implement JWT parsing and user mapping
- [ ] Add comprehensive audit logging
- [ ] Handle authentication errors gracefully
- [ ] Add metrics for auth success/failure rates

**Testing:**
```go
func TestEndToEndAuth(t *testing.T) {
    // Setup
    policy := &policy.Policy{...}
    verifier, _ := policy.NewVerifier(policy)

    mockSTS := httptest.NewServer(mockSTSHandler())
    stsClient := NewSTSClient(mockSTS.URL)

    dpopKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    auth := NewAuthenticator(verifier, stsClient, dpopKey)

    // Create client cert with valid attestation
    evidence := mockValidAttestation()
    clientCert := tlsext.CreateCertificateWithAttestation(evidence, ...)

    startupMsg := &pgproto3.StartupMessage{
        Parameters: map[string]string{
            "user":     "alice",
            "database": "defaultdb",
        },
    }

    // Authenticate
    result, err := auth.AuthenticateRequest(clientCert, startupMsg)
    require.NoError(t, err)
    assert.True(t, result.Allowed)
    assert.NotEmpty(t, result.CRDBUser)

    // Test with invalid attestation
    badCert := tlsext.CreateCertificateWithAttestation(mockInvalidAttestation(), ...)
    result, _ = auth.AuthenticateRequest(badCert, startupMsg)
    assert.False(t, result.Allowed)
}
```

**Deliverable:** Complete authentication flow from client to CRDB

**Success Criteria:**
- Client with valid attestation can connect
- Client with invalid attestation is rejected
- User mapping works correctly
- All decisions are audit logged
- Metrics track authentication rates

---

## Phase 4: GCP Deployment & Production Features (2-3 weeks)

### 4.1 GCP Confidential VM Infrastructure

**File:** `iac/terraform/main.tf`
```hcl
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# VPC Network
resource "google_compute_network" "atls_network" {
  name                    = "atls-proxy-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "atls_subnet" {
  name          = "atls-proxy-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.atls_network.id
}

# Firewall rules
resource "google_compute_firewall" "allow_proxy" {
  name    = "allow-proxy-inbound"
  network = google_compute_network.atls_network.name

  allow {
    protocol = "tcp"
    ports    = ["26257"] # CockroachDB port
  }

  source_ranges = var.allowed_client_ips
  target_tags   = ["atls-proxy"]
}

resource "google_compute_firewall" "deny_direct_crdb" {
  name    = "deny-direct-crdb"
  network = google_compute_network.atls_network.name

  deny {
    protocol = "tcp"
    ports    = ["26257"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["cockroachdb"]
  priority      = 1000
}

# SEV-SNP Confidential VM
resource "google_compute_instance" "atls_proxy" {
  name         = "cockroachdb-atls-proxy"
  machine_type = "n2d-standard-4"
  zone         = "${var.region}-a"

  tags = ["atls-proxy"]

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = 20
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.atls_subnet.id

    access_config {
      // Ephemeral public IP
    }
  }

  # SEV-SNP configuration
  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "SEV_SNP"
  }

  # AMD Milan CPU required for SEV-SNP
  min_cpu_platform = "AMD Milan"

  # Confidential VMs must use TERMINATE maintenance policy
  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  metadata = {
    startup-script = file("${path.module}/startup.sh")
  }

  service_account {
    email  = google_service_account.proxy_sa.email
    scopes = ["cloud-platform"]
  }
}

# Service account for proxy
resource "google_service_account" "proxy_sa" {
  account_id   = "atls-proxy-sa"
  display_name = "Attested TLS Proxy Service Account"
}

# Secret Manager for certificates
resource "google_secret_manager_secret" "proxy_cert" {
  secret_id = "proxy-client-cert"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "proxy_cert_version" {
  secret      = google_secret_manager_secret.proxy_cert.id
  secret_data = file("${path.module}/../../certs/client.proxy.crt")
}

resource "google_secret_manager_secret_iam_member" "proxy_cert_access" {
  secret_id = google_secret_manager_secret.proxy_cert.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.proxy_sa.email}"
}

# Health check
resource "google_compute_health_check" "atls_proxy_health" {
  name                = "atls-proxy-health"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = "8080" # Health endpoint
  }
}

# Outputs
output "proxy_ip" {
  value = google_compute_instance.atls_proxy.network_interface[0].access_config[0].nat_ip
}

output "proxy_internal_ip" {
  value = google_compute_instance.atls_proxy.network_interface[0].network_ip
}
```

**File:** `iac/terraform/variables.tf`
```hcl
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "allowed_client_ips" {
  description = "IP ranges allowed to connect to proxy"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict in production
}

variable "crdb_backend_host" {
  description = "CockroachDB backend hostname"
  type        = string
}

variable "crdb_backend_port" {
  description = "CockroachDB backend port"
  type        = number
  default     = 26257
}
```

**File:** `iac/terraform/startup.sh`
```bash
#!/bin/bash
set -e

# Update system
apt-get update
apt-get install -y golang-go build-essential jq

# Verify SEV-SNP is available
if ! dmesg | grep -i sev-snp; then
    echo "WARNING: SEV-SNP not detected"
fi

# Install proxy binary (from Cloud Storage or build from source)
mkdir -p /opt/atls-proxy
cd /opt/atls-proxy

# Option 1: Download pre-built binary
gsutil cp gs://${PROJECT_ID}-artifacts/atls-proxy-latest /usr/local/bin/atls-proxy
chmod +x /usr/local/bin/atls-proxy

# Option 2: Build from source
# git clone https://github.com/souravcrl/attested-tls-proxy-cockroach.git
# cd attested-tls-proxy-cockroach
# make build
# cp bin/proxy /usr/local/bin/atls-proxy

# Fetch certificates from Secret Manager
gcloud secrets versions access latest --secret="proxy-client-cert" > /opt/atls-proxy/client.crt
gcloud secrets versions access latest --secret="proxy-client-key" > /opt/atls-proxy/client.key

# Create config file
cat > /opt/atls-proxy/config.yaml <<EOF
proxy:
  listen: "0.0.0.0:26257"
  backend:
    host: "${CRDB_HOST}"
    port: 26257
    tls:
      enabled: true
      ca_cert: "/opt/atls-proxy/ca.crt"
      client_cert: "/opt/atls-proxy/client.crt"
      client_key: "/opt/atls-proxy/client.key"

attestation:
  provider: "sev-snp"
  policy_file: "/opt/atls-proxy/policy.yaml"

tokens:
  sts_url: "${STS_URL}"
  dpop_enabled: true

logging:
  level: "info"
  audit_file: "/var/log/atls-proxy/audit.json"
EOF

# Create systemd service
cat > /etc/systemd/system/atls-proxy.service <<EOF
[Unit]
Description=Attested TLS Proxy
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/atls-proxy --config /opt/atls-proxy/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable atls-proxy
systemctl start atls-proxy

echo "Proxy deployed successfully"
```

**Tasks:**
- [ ] Create Terraform configuration for SEV-SNP VM
- [ ] Configure VPC and firewall rules
- [ ] Setup Secret Manager for certificate storage
- [ ] Create startup script for automated deployment
- [ ] Configure service account with minimal permissions
- [ ] Add health checks and monitoring

**Deployment:**
```bash
cd iac/terraform
terraform init
terraform plan -var="project_id=my-gcp-project" -var="crdb_backend_host=10.0.2.10"
terraform apply
```

**Deliverable:** Automated GCP infrastructure deployment

---

### 4.2 Run CockroachDB in Same SEV-SNP VM

**Objective:** Move CockroachDB into the same SEV-SNP VM as the proxy for full end-to-end attestation

**Updated Architecture:**
```
┌────────────────── SEV-SNP VM ──────────────────┐
│                                                 │
│  ┌────────┐ Unix Socket ┌──────────────┐      │
│  │ Proxy  │────────────>│ CockroachDB  │      │
│  │ :26257 │             │  (localhost) │      │
│  └────────┘             └──────────────┘      │
│       ▲                                        │
│       │ aTLS (port 26257)                     │
└───────┼────────────────────────────────────────┘
        │
   ┌────────┐
   │ Client │
   └────────┘
```

**File:** `scripts/deploy_crdb_in_tee.sh`
```bash
#!/bin/bash
set -e

CRDB_VERSION="v24.1.0"
CRDB_DIR="/opt/cockroachdb"
CERTS_DIR="/opt/atls-proxy/certs"

# Download CockroachDB binary
wget "https://binaries.cockroachdb.com/cockroach-${CRDB_VERSION}.linux-amd64.tgz"
tar xzf "cockroach-${CRDB_VERSION}.linux-amd64.tgz"
cp "cockroach-${CRDB_VERSION}.linux-amd64/cockroach" /usr/local/bin/
chmod +x /usr/local/bin/cockroach

# Create CRDB data directory
mkdir -p "${CRDB_DIR}/data"

# Initialize CRDB cluster
cockroach init --insecure --host=localhost:26258

# Create systemd service for CRDB
cat > /etc/systemd/system/cockroachdb.service <<EOF
[Unit]
Description=CockroachDB
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/cockroach start-single-node \\
    --listen-addr=localhost:26258 \\
    --http-addr=localhost:8080 \\
    --store=${CRDB_DIR}/data \\
    --certs-dir=${CERTS_DIR} \\
    --log="{sinks: {stderr: {filter: INFO}}}"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cockroachdb
systemctl start cockroachdb

# Wait for CRDB to start
sleep 5

# Configure HBA to only allow local proxy
cockroach sql --host=localhost:26258 --certs-dir=${CERTS_DIR} <<SQL
SET CLUSTER SETTING server.host_based_authentication.configuration = '
local all all trust
hostssl all all 127.0.0.1/32 cert
hostssl all all ::1/128 cert
hostssl all all 0.0.0.0/0 reject
';
SQL

echo "CockroachDB running in TEE, accessible only via localhost"
```

**Update Proxy Config:** `config/proxy.yaml`
```yaml
proxy:
  listen: "0.0.0.0:26257"  # External clients connect here
  backend:
    # Connect to CRDB via Unix socket (best performance)
    unix_socket: "/var/run/cockroachdb/cockroach.sock"
    # OR via localhost TCP
    host: "localhost"
    port: 26258
    tls:
      enabled: true
      ca_cert: "/opt/atls-proxy/certs/ca.crt"
      client_cert: "/opt/atls-proxy/certs/client.proxy.crt"
      client_key: "/opt/atls-proxy/certs/client.proxy.key"
```

**Update Terraform:** `iac/terraform/main.tf`
```hcl
resource "google_compute_instance" "atls_proxy" {
  # ... existing config ...

  # Larger machine for running both proxy and CRDB
  machine_type = "n2d-standard-8"

  boot_disk {
    initialize_params {
      size = 100 # More space for CRDB data
    }
  }

  metadata = {
    startup-script = <<-EOT
      #!/bin/bash
      ${file("${path.module}/startup.sh")}
      ${file("${path.module}/../scripts/deploy_crdb_in_tee.sh")}
    EOT
  }
}
```

**Updated Measurement Policy:** `config/policy.yaml`
```yaml
measurements:
  - name: "kernel"
    sha384: "..." # Kernel measurement
  - name: "proxy"
    sha384: "..." # Proxy binary measurement
  - name: "cockroachdb"
    sha384: "..." # CRDB binary measurement

tcb_version_min: "1.51"
nonce_ttl: 300s
```

**Generate Measurements:** `scripts/generate_measurements.sh`
```bash
#!/bin/bash

# Measure proxy binary
PROXY_HASH=$(sha384sum /usr/local/bin/atls-proxy | awk '{print $1}')
echo "Proxy measurement: $PROXY_HASH"

# Measure CockroachDB binary
CRDB_HASH=$(sha384sum /usr/local/bin/cockroach | awk '{print $1}')
echo "CockroachDB measurement: $CRDB_HASH"

# Update policy file
cat > /opt/atls-proxy/policy.yaml <<EOF
measurements:
  - name: "proxy"
    sha384: "${PROXY_HASH}"
  - name: "cockroachdb"
    sha384: "${CRDB_HASH}"
tcb_version_min: "1.51"
nonce_ttl: 300s
EOF

echo "Measurements updated in policy.yaml"
```

**Tasks:**
- [ ] Install CockroachDB in SEV-SNP VM
- [ ] Configure CRDB to listen on localhost only
- [ ] Update proxy to connect via Unix socket or localhost
- [ ] Include CRDB binary in attestation measurements
- [ ] Update policy to verify both proxy and CRDB
- [ ] Test full end-to-end attestation
- [ ] Document the complete setup

**Benefits:**
- Complete attestation of data path (client → proxy → CRDB)
- No network exposure of CRDB
- Shared TEE memory space
- Simplified deployment (single VM)

**Deliverable:** Full-stack TEE with both proxy and CockroachDB

---

### 4.3 Production Features

**Monitoring:** `pkg/metrics/metrics.go`
```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    AttestationVerifications = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "atls_attestation_verifications_total",
            Help: "Total attestation verifications",
        },
        []string{"result"}, // "success" or "failure"
    )

    AttestationFailures = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "atls_attestation_failures_total",
            Help: "Failed attestation attempts",
        },
        []string{"reason"}, // "measurement_mismatch", "nonce_replay", etc.
    )

    PolicyViolations = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "atls_policy_violations_total",
            Help: "Policy enforcement denials",
        },
    )

    TokenIssues = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "atls_token_issues_total",
            Help: "STS token issuances",
        },
    )

    BackendRequests = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "atls_backend_requests_total",
            Help: "Forwarded backend requests",
        },
        []string{"status"}, // "success" or "error"
    )

    ConnectionDuration = promauto.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "atls_connection_duration_seconds",
            Help:    "Connection duration",
            Buckets: prometheus.DefBuckets,
        },
    )
)
```

**Health Checks:** `cmd/proxy/health.go`
```go
package main

import (
    "encoding/json"
    "net/http"
)

type HealthResponse struct {
    Status      string            `json:"status"`
    Checks      map[string]string `json:"checks"`
    Attestation bool              `json:"attestation_ready"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    health := HealthResponse{
        Status: "healthy",
        Checks: map[string]string{
            "backend":     checkBackend(),
            "sts":         checkSTS(),
            "attestation": checkAttestation(),
        },
        Attestation: checkAttestation() == "ok",
    }

    if health.Checks["backend"] != "ok" || health.Checks["sts"] != "ok" {
        health.Status = "degraded"
        w.WriteHeader(http.StatusServiceUnavailable)
    }

    json.NewEncoder(w).Encode(health)
}

func startHealthServer() {
    http.HandleFunc("/health", healthHandler)
    http.HandleFunc("/ready", readyHandler)
    http.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)

    http.ListenAndServe(":8080", nil)
}
```

**Graceful Shutdown:** `cmd/proxy/main.go`
```go
func main() {
    // ... setup ...

    // Start health server
    go startHealthServer()

    // Start proxy
    go proxy.Start()

    // Wait for shutdown signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan

    log.Info("Shutting down gracefully...")

    // Stop accepting new connections
    proxy.Stop()

    // Wait for existing connections to finish (with timeout)
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    proxy.WaitForConnections(ctx)

    log.Info("Shutdown complete")
}
```

**Tasks:**
- [ ] Add Prometheus metrics
- [ ] Implement health check endpoints
- [ ] Add graceful shutdown handling
- [ ] Implement connection pooling with limits
- [ ] Add rate limiting per client
- [ ] Implement circuit breaker for STS failures
- [ ] Add comprehensive audit logging
- [ ] Setup log aggregation (Cloud Logging)

**Deliverable:** Production-ready proxy with observability

---

### 4.4 Client Attestation Storage & HTTP API

**Objective:** Store client attestation data locally and expose HTTP API for dashboard aggregation

**File:** `pkg/attestation/store.go`
```go
package attestation

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "time"
    _ "github.com/mattn/go-sqlite3"
)

type AttestationStore struct {
    db *sql.DB
}

type ClientAttestation struct {
    ID             string    `json:"id"`
    ClientID       string    `json:"client_id"`        // Derived from measurement
    Measurement    string    `json:"measurement"`       // SHA-384 hex
    TCBVersion     string    `json:"tcb_version"`
    DebugEnabled   bool      `json:"debug_enabled"`
    SMTEnabled     bool      `json:"smt_enabled"`
    Nonce          string    `json:"nonce"`
    Timestamp      time.Time `json:"timestamp"`
    VerifyResult   string    `json:"verify_result"`    // "allowed" or "denied"
    VerifyReason   string    `json:"verify_reason"`
    ConnectedAt    time.Time `json:"connected_at"`
    DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
    BytesIn        int64     `json:"bytes_in"`
    BytesOut       int64     `json:"bytes_out"`
    ProxyNodeID    string    `json:"proxy_node_id"`    // This proxy's ID
}

func NewAttestationStore(dbPath string) (*AttestationStore, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, err
    }

    // Create schema
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS client_attestations (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            measurement TEXT NOT NULL,
            tcb_version TEXT,
            debug_enabled BOOLEAN,
            smt_enabled BOOLEAN,
            nonce TEXT,
            timestamp DATETIME,
            verify_result TEXT,
            verify_reason TEXT,
            connected_at DATETIME,
            disconnected_at DATETIME,
            bytes_in INTEGER DEFAULT 0,
            bytes_out INTEGER DEFAULT 0,
            proxy_node_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_client_id ON client_attestations(client_id);
        CREATE INDEX IF NOT EXISTS idx_connected_at ON client_attestations(connected_at);
        CREATE INDEX IF NOT EXISTS idx_verify_result ON client_attestations(verify_result);
    `)
    if err != nil {
        return nil, err
    }

    return &AttestationStore{db: db}, nil
}

func (s *AttestationStore) RecordAttestation(att *ClientAttestation) error {
    _, err := s.db.Exec(`
        INSERT INTO client_attestations (
            id, client_id, measurement, tcb_version, debug_enabled, smt_enabled,
            nonce, timestamp, verify_result, verify_reason, connected_at, proxy_node_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, att.ID, att.ClientID, att.Measurement, att.TCBVersion, att.DebugEnabled,
       att.SMTEnabled, att.Nonce, att.Timestamp, att.VerifyResult, att.VerifyReason,
       att.ConnectedAt, att.ProxyNodeID)
    return err
}

func (s *AttestationStore) UpdateConnectionStats(id string, bytesIn, bytesOut int64) error {
    _, err := s.db.Exec(`
        UPDATE client_attestations
        SET bytes_in = ?, bytes_out = ?, disconnected_at = ?
        WHERE id = ?
    `, bytesIn, bytesOut, time.Now(), id)
    return err
}

func (s *AttestationStore) GetRecentAttestations(limit int) ([]*ClientAttestation, error) {
    rows, err := s.db.Query(`
        SELECT id, client_id, measurement, tcb_version, debug_enabled, smt_enabled,
               nonce, timestamp, verify_result, verify_reason, connected_at,
               disconnected_at, bytes_in, bytes_out, proxy_node_id
        FROM client_attestations
        ORDER BY connected_at DESC
        LIMIT ?
    `, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var attestations []*ClientAttestation
    for rows.Next() {
        att := &ClientAttestation{}
        err := rows.Scan(&att.ID, &att.ClientID, &att.Measurement, &att.TCBVersion,
            &att.DebugEnabled, &att.SMTEnabled, &att.Nonce, &att.Timestamp,
            &att.VerifyResult, &att.VerifyReason, &att.ConnectedAt,
            &att.DisconnectedAt, &att.BytesIn, &att.BytesOut, &att.ProxyNodeID)
        if err != nil {
            return nil, err
        }
        attestations = append(attestations, att)
    }
    return attestations, nil
}

func (s *AttestationStore) GetActiveClients() ([]*ClientAttestation, error) {
    rows, err := s.db.Query(`
        SELECT id, client_id, measurement, tcb_version, debug_enabled, smt_enabled,
               nonce, timestamp, verify_result, verify_reason, connected_at,
               disconnected_at, bytes_in, bytes_out, proxy_node_id
        FROM client_attestations
        WHERE disconnected_at IS NULL AND verify_result = 'allowed'
        ORDER BY connected_at DESC
    `)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var clients []*ClientAttestation
    for rows.Next() {
        att := &ClientAttestation{}
        err := rows.Scan(&att.ID, &att.ClientID, &att.Measurement, &att.TCBVersion,
            &att.DebugEnabled, &att.SMTEnabled, &att.Nonce, &att.Timestamp,
            &att.VerifyResult, &att.VerifyReason, &att.ConnectedAt,
            &att.DisconnectedAt, &att.BytesIn, &att.BytesOut, &att.ProxyNodeID)
        if err != nil {
            return nil, err
        }
        clients = append(clients, att)
    }
    return clients, nil
}

func (s *AttestationStore) GetStatsByMeasurement() (map[string]int, error) {
    rows, err := s.db.Query(`
        SELECT measurement, COUNT(*) as count
        FROM client_attestations
        WHERE verify_result = 'allowed'
        GROUP BY measurement
    `)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    stats := make(map[string]int)
    for rows.Next() {
        var measurement string
        var count int
        if err := rows.Scan(&measurement, &count); err != nil {
            return nil, err
        }
        stats[measurement] = count
    }
    return stats, nil
}
```

**File:** `pkg/api/http_server.go`
```go
package api

import (
    "encoding/json"
    "net/http"
    "strconv"
    "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/attestation"
)

type Server struct {
    store      *attestation.AttestationStore
    proxyNodeID string
}

func NewServer(store *attestation.AttestationStore, nodeID string) *Server {
    return &Server{
        store:       store,
        proxyNodeID: nodeID,
    }
}

func (s *Server) Start(addr string) error {
    http.HandleFunc("/api/v1/attestations", s.handleAttestations)
    http.HandleFunc("/api/v1/clients", s.handleClients)
    http.HandleFunc("/api/v1/clients/active", s.handleActiveClients)
    http.HandleFunc("/api/v1/stats/measurements", s.handleMeasurementStats)
    http.HandleFunc("/api/v1/health", s.handleHealth)
    http.HandleFunc("/api/v1/node/info", s.handleNodeInfo)

    return http.ListenAndServe(addr, nil)
}

func (s *Server) handleAttestations(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    limit := 100
    if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
        if l, err := strconv.Atoi(limitStr); err == nil {
            limit = l
        }
    }

    attestations, err := s.store.GetRecentAttestations(limit)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "proxy_node_id": s.proxyNodeID,
        "count":         len(attestations),
        "attestations":  attestations,
    })
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Get client ID from URL if specified
    clientID := r.URL.Query().Get("client_id")
    if clientID != "" {
        // TODO: Implement GetByClientID
        http.Error(w, "Not implemented", http.StatusNotImplemented)
        return
    }

    attestations, err := s.store.GetRecentAttestations(100)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "proxy_node_id": s.proxyNodeID,
        "clients":       attestations,
    })
}

func (s *Server) handleActiveClients(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    clients, err := s.store.GetActiveClients()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "proxy_node_id": s.proxyNodeID,
        "count":         len(clients),
        "active_clients": clients,
    })
}

func (s *Server) handleMeasurementStats(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    stats, err := s.store.GetStatsByMeasurement()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "proxy_node_id": s.proxyNodeID,
        "measurements":  stats,
    })
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":        "healthy",
        "proxy_node_id": s.proxyNodeID,
    })
}

func (s *Server) handleNodeInfo(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "node_id":   s.proxyNodeID,
        "version":   "1.0.0", // TODO: Get from build info
        "timestamp": time.Now(),
    })
}
```

**Configuration Update:** `config/proxy.yaml`
```yaml
proxy:
  listen: "0.0.0.0:26257"
  node_id: "proxy-1"  # Unique identifier for this proxy node
  backend:
    host: "localhost"
    port: 26258

attestation:
  provider: "sev-snp"
  policy_file: "/etc/atls-proxy/policy.yaml"
  storage:
    db_path: "/var/lib/atls-proxy/attestations.db"
    retention_days: 90

api:
  listen: "0.0.0.0:8080"
  enabled: true
```

**Integration into Proxy:** `pkg/backend/proxy.go` (updated)
```go
func (p *Proxy) handleConnection(clientConn *tls.Conn) {
    // 1. Get client certificate
    clientCert := clientConn.ConnectionState().PeerCertificates[0]

    // 2. Extract attestation from client certificate
    eat, err := tlsext.ExtractAttestationExtension(clientCert)
    if err != nil {
        log.Error("No attestation in certificate", err)
        return
    }

    // 3. Verify attestation
    verifyResult, err := p.verifier.VerifyAttestation(eat)

    // 4. Record attestation in local store
    clientAtt := &attestation.ClientAttestation{
        ID:           uuid.New().String(),
        ClientID:     hex.EncodeToString(eat.Measurements.Application[:8]), // Use first 8 bytes as ID
        Measurement:  hex.EncodeToString(eat.Measurements.Application),
        TCBVersion:   eat.TCBVersion,
        DebugEnabled: eat.Report.IsDebugEnabled(),
        SMTEnabled:   eat.Report.IsSMTEnabled(),
        Nonce:        hex.EncodeToString(eat.Nonce),
        Timestamp:    time.Unix(eat.Timestamp, 0),
        VerifyResult: "denied",
        VerifyReason: "Unknown",
        ConnectedAt:  time.Now(),
        ProxyNodeID:  p.config.NodeID,
    }

    if verifyResult.Allowed {
        clientAtt.VerifyResult = "allowed"
        clientAtt.VerifyReason = verifyResult.Reason
    } else {
        clientAtt.VerifyResult = "denied"
        clientAtt.VerifyReason = verifyResult.Reason
    }

    if err := p.attestationStore.RecordAttestation(clientAtt); err != nil {
        log.Error("Failed to record attestation", err)
    }

    if !verifyResult.Allowed {
        return // Reject connection
    }

    // 5. Connect to backend and track stats
    backendConn, err := p.backend.Get()
    if err != nil {
        log.Error("Failed to connect to backend", err)
        return
    }

    // 6. Forward traffic and track bytes
    bytesIn, bytesOut := p.forwardTraffic(clientConn, backendConn)

    // 7. Update connection stats on disconnect
    p.attestationStore.UpdateConnectionStats(clientAtt.ID, bytesIn, bytesOut)
}
```

**Tasks:**
- [ ] Implement SQLite-based attestation storage
- [ ] Create HTTP API endpoints for attestation data
- [ ] Add data retention policies
- [ ] Implement pagination for large result sets
- [ ] Add filtering by time range, measurement, verify result
- [ ] Track connection statistics (bytes in/out, duration)
- [ ] Add index on frequently queried fields

**Deliverable:** Local attestation storage with HTTP API for remote queries

---

### 4.5 Centralized Dashboard for Cluster-Wide Attestation

**Objective:** Build web dashboard that queries all proxy nodes and aggregates attestation data

**File:** `cmd/dashboard/main.go`
```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "time"
)

type ProxyNode struct {
    ID      string `json:"id"`
    Address string `json:"address"`
    Healthy bool   `json:"healthy"`
}

type AggregatedData struct {
    TotalClients        int                            `json:"total_clients"`
    ActiveClients       int                            `json:"active_clients"`
    AttestationsByProxy map[string]int                 `json:"attestations_by_proxy"`
    MeasurementStats    map[string]int                 `json:"measurement_stats"`
    Clients             []ClientAttestationWithProxy   `json:"clients"`
    LastUpdated         time.Time                      `json:"last_updated"`
}

type ClientAttestationWithProxy struct {
    ClientAttestation
    ProxyAddress string `json:"proxy_address"`
}

type Dashboard struct {
    proxyNodes []ProxyNode
    cache      *AggregatedData
    cacheMutex sync.RWMutex
}

func NewDashboard(nodes []ProxyNode) *Dashboard {
    return &Dashboard{
        proxyNodes: nodes,
        cache:      &AggregatedData{},
    }
}

func (d *Dashboard) Start() {
    // Refresh data every 10 seconds
    go d.refreshLoop()

    // Start HTTP server
    http.HandleFunc("/", d.handleIndex)
    http.HandleFunc("/api/aggregated", d.handleAggregated)
    http.HandleFunc("/api/topology", d.handleTopology)

    fmt.Println("Dashboard listening on :9090")
    http.ListenAndServe(":9090", nil)
}

func (d *Dashboard) refreshLoop() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for {
        d.refreshData()
        <-ticker.C
    }
}

func (d *Dashboard) refreshData() {
    var wg sync.WaitGroup
    var mutex sync.Mutex

    aggregated := &AggregatedData{
        AttestationsByProxy: make(map[string]int),
        MeasurementStats:    make(map[string]int),
        Clients:             []ClientAttestationWithProxy{},
        LastUpdated:         time.Now(),
    }

    // Query all proxy nodes in parallel
    for _, node := range d.proxyNodes {
        wg.Add(1)
        go func(n ProxyNode) {
            defer wg.Done()

            // Query active clients from this proxy
            resp, err := http.Get(fmt.Sprintf("http://%s/api/v1/clients/active", n.Address))
            if err != nil {
                fmt.Printf("Failed to query proxy %s: %v\n", n.ID, err)
                return
            }
            defer resp.Body.Close()

            var result struct {
                ProxyNodeID   string                `json:"proxy_node_id"`
                Count         int                   `json:"count"`
                ActiveClients []ClientAttestation   `json:"active_clients"`
            }

            if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
                fmt.Printf("Failed to decode response from %s: %v\n", n.ID, err)
                return
            }

            // Aggregate data
            mutex.Lock()
            aggregated.AttestationsByProxy[n.ID] = result.Count
            aggregated.TotalClients += result.Count
            aggregated.ActiveClients += result.Count

            for _, client := range result.ActiveClients {
                aggregated.Clients = append(aggregated.Clients, ClientAttestationWithProxy{
                    ClientAttestation: client,
                    ProxyAddress:      n.Address,
                })

                // Aggregate measurement stats
                if count, ok := aggregated.MeasurementStats[client.Measurement]; ok {
                    aggregated.MeasurementStats[client.Measurement] = count + 1
                } else {
                    aggregated.MeasurementStats[client.Measurement] = 1
                }
            }
            mutex.Unlock()
        }(node)
    }

    wg.Wait()

    // Update cache
    d.cacheMutex.Lock()
    d.cache = aggregated
    d.cacheMutex.Unlock()
}

func (d *Dashboard) handleAggregated(w http.ResponseWriter, r *http.Request) {
    d.cacheMutex.RLock()
    data := d.cache
    d.cacheMutex.RUnlock()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}

func (d *Dashboard) handleTopology(w http.ResponseWriter, r *http.Request) {
    // Return cluster topology (proxy nodes and their clients)
    d.cacheMutex.RLock()
    defer d.cacheMutex.RUnlock()

    topology := map[string]interface{}{
        "nodes":   d.proxyNodes,
        "clients": d.cache.Clients,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(topology)
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
    // Serve HTML dashboard
    html := `
<!DOCTYPE html>
<html>
<head>
    <title>Attestation Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .stat-card h3 { margin-top: 0; }
        .stat-card .value { font-size: 2em; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        .allowed { color: green; }
        .denied { color: red; }
    </style>
</head>
<body>
    <h1>Cluster Attestation Dashboard</h1>

    <div class="stats">
        <div class="stat-card">
            <h3>Total Clients</h3>
            <div class="value" id="totalClients">-</div>
        </div>
        <div class="stat-card">
            <h3>Active Connections</h3>
            <div class="value" id="activeClients">-</div>
        </div>
        <div class="stat-card">
            <h3>Proxy Nodes</h3>
            <div class="value" id="proxyNodes">-</div>
        </div>
    </div>

    <h2>Active Clients by Measurement</h2>
    <canvas id="measurementChart" width="400" height="200"></canvas>

    <h2>Connected Clients</h2>
    <table id="clientsTable">
        <thead>
            <tr>
                <th>Client ID</th>
                <th>Measurement</th>
                <th>TCB Version</th>
                <th>Debug</th>
                <th>Connected At</th>
                <th>Proxy Node</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>

    <script>
        function updateDashboard() {
            fetch('/api/aggregated')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('totalClients').textContent = data.total_clients;
                    document.getElementById('activeClients').textContent = data.active_clients;
                    document.getElementById('proxyNodes').textContent = Object.keys(data.attestations_by_proxy).length;

                    // Update measurement chart
                    const labels = Object.keys(data.measurement_stats);
                    const values = Object.values(data.measurement_stats);

                    new Chart(document.getElementById('measurementChart'), {
                        type: 'bar',
                        data: {
                            labels: labels.map(l => l.substring(0, 12) + '...'),
                            datasets: [{
                                label: 'Clients by Measurement',
                                data: values,
                                backgroundColor: 'rgba(75, 192, 192, 0.6)'
                            }]
                        }
                    });

                    // Update clients table
                    const tbody = document.querySelector('#clientsTable tbody');
                    tbody.innerHTML = '';
                    data.clients.forEach(client => {
                        const row = tbody.insertRow();
                        row.innerHTML = \`
                            <td>\${client.client_id}</td>
                            <td>\${client.measurement.substring(0, 16)}...</td>
                            <td>\${client.tcb_version}</td>
                            <td>\${client.debug_enabled ? 'Yes' : 'No'}</td>
                            <td>\${new Date(client.connected_at).toLocaleString()}</td>
                            <td>\${client.proxy_address}</td>
                            <td class="\${client.verify_result}">\${client.verify_result}</td>
                        \`;
                    });
                });
        }

        // Update every 10 seconds
        updateDashboard();
        setInterval(updateDashboard, 10000);
    </script>
</body>
</html>
    `
    w.Header().Set("Content-Type", "text/html")
    w.Write([]byte(html))
}

func main() {
    // Configure proxy nodes to query
    nodes := []ProxyNode{
        {ID: "proxy-1", Address: "10.0.1.10:8080", Healthy: true},
        {ID: "proxy-2", Address: "10.0.1.11:8080", Healthy: true},
        {ID: "proxy-3", Address: "10.0.1.12:8080", Healthy: true},
    }

    dashboard := NewDashboard(nodes)
    dashboard.Start()
}
```

**Configuration:** `config/dashboard.yaml`
```yaml
dashboard:
  listen: ":9090"
  refresh_interval: 10s

  proxy_nodes:
    - id: "proxy-1"
      address: "10.0.1.10:8080"
    - id: "proxy-2"
      address: "10.0.1.11:8080"
    - id: "proxy-3"
      address: "10.0.1.12:8080"

  # Auto-discover nodes from CRDB cluster (optional)
  auto_discovery:
    enabled: true
    crdb_sql_url: "postgresql://root@localhost:26257/defaultdb"
    query: "SELECT node_id, address FROM crdb_internal.gossip_nodes"
```

**Tasks:**
- [ ] Implement parallel HTTP queries to all proxy nodes
- [ ] Aggregate attestation data from multiple proxies
- [ ] Build web UI with real-time updates
- [ ] Add visualization for measurement distribution
- [ ] Show cluster topology (which clients connect to which nodes)
- [ ] Implement auto-discovery of proxy nodes from CRDB cluster
- [ ] Add filtering and search capabilities
- [ ] Export compliance reports (CSV, JSON, PDF)
- [ ] Add alerting for policy violations

**Deliverable:** Centralized dashboard with cluster-wide attestation visibility

**Success Criteria:**
- Dashboard queries all proxy nodes in <1 second
- Real-time updates every 10 seconds
- Shows active clients across entire cluster
- Visualizes measurement distribution
- Exports compliance reports

---

## Phase 5: Testing & Documentation (1-2 weeks)

### 5.1 Testing Strategy

**Unit Tests:**
```bash
make test-unit
# Tests all packages with >80% coverage
```

**Integration Tests:**
```bash
make test-integration
# Requires: running CRDB, mock STS
```

**E2E Tests:** `tests/e2e/full_flow_test.go`
```go
func TestFullAttestationFlow(t *testing.T) {
    // 1. Start proxy with real SEV-SNP (or mock)
    // 2. Generate client attestation
    // 3. Connect through proxy
    // 4. Execute SQL queries
    // 5. Verify audit logs
    // 6. Check metrics
}
```

**Load Tests:** `tests/load/benchmark.go`
```go
func BenchmarkProxyThroughput(b *testing.B) {
    // Measure queries/sec with attestation overhead
}
```

---

### 5.2 Documentation

**Files to Create:**
- [x] `PLAN.md` - This file
- [ ] `docs/ARCHITECTURE.md` - Detailed architecture
- [ ] `docs/DEPLOYMENT.md` - Step-by-step deployment guide
- [ ] `docs/SECURITY.md` - Threat model and mitigations
- [ ] `docs/DEVELOPMENT.md` - Local development setup
- [ ] `docs/TROUBLESHOOTING.md` - Common issues
- [ ] API documentation (godoc comments)

---

## Summary & Recommendations

### Phased Approach Benefits

1. **Phase 1-3**: Validates architecture with proxy-only TEE
   - Faster development
   - Easier testing
   - Proves attestation concept

2. **Phase 4**: Adds full end-to-end attestation
   - Complete confidential computing
   - Maximum security guarantees
   - Production-ready deployment

### Critical Success Factors

- **Measurement Management**: Automate measurement generation and updates
- **Nonce Freshness**: Prevent replay attacks with strict TTLs
- **Signature Verification**: Properly validate AMD certificate chains
- **Audit Logging**: Comprehensive logging for compliance
- **Monitoring**: Track attestation success/failure rates

### Next Steps

1. **Immediate**: Start Phase 1.1 (project setup)
2. **Week 1-2**: Complete Phase 1 (local proxy + attestation)
3. **Week 3-4**: Complete Phase 2 (TLS extensions)
4. **Week 5-6**: Complete Phase 3 (auth flow)
5. **Week 7-8**: Complete Phase 4 (GCP deployment + CRDB in TEE)
6. **Week 9**: Testing and documentation

### Questions to Resolve

1. **STS Provider**: Will you use an existing STS (e.g., GCP STS) or build custom?
2. **Verifier Service**: Use Veraison, Azure Attestation, or custom verifier?
   - **Current Decision (Phase 2.5)**: Embedded verifier (valid per RFC 9334 Section 7.2.2)
   - **Future (Phase 3.3)**: Optional external verifier support
3. **Certificate Management**: How will you rotate proxy certificates?
4. **Multi-tenant**: Will you support multiple CRDB tenants through one proxy?
5. **Reference Value Distribution**: How to distribute measurements?
   - **Current (Phase 2.5)**: Local YAML policy file
   - **Planned (Phase 3.1)**: AMD KDS for certificate endorsements
   - **Planned (Phase 3.2)**: CoRIM repositories for measurements
   - **Planned (Phase 3.3)**: External verifier with RVPS

---

## Phase 3 Extensions: Reference Value Distribution & External Verifiers

### 3.1 AMD KDS Integration (Vendor Endorsements)

**Objective:** Automatically fetch and cache AMD certificate chains instead of manual configuration

**File:** `pkg/attestation/kds_client.go`
```go
package attestation

import (
    "fmt"
    "net/http"
    "time"
)

type KDSClient struct {
    baseURL     string
    httpClient  *http.Client
    certCache   map[string]*CachedCertChain
    cacheMutex  sync.RWMutex
}

type CachedCertChain struct {
    VCEK      []byte
    ASK       []byte
    ARK       []byte
    FetchedAt time.Time
}

func NewKDSClient() *KDSClient {
    return &KDSClient{
        baseURL: "https://kdsintf.amd.com",
        httpClient: &http.Client{Timeout: 10 * time.Second},
        certCache: make(map[string]*CachedCertChain),
    }
}

// FetchCertificateChain downloads VCEK, ASK, ARK from AMD KDS
func (k *KDSClient) FetchCertificateChain(chipID [64]byte, tcbVersion string) (*CachedCertChain, error) {
    chipIDHex := hex.EncodeToString(chipID[:])

    // Check cache first (valid for 24 hours)
    k.certCacheMutex.RLock()
    cached, ok := k.certCache[chipIDHex]
    k.certCacheMutex.RUnlock()
    if ok && time.Since(cached.FetchedAt) < 24*time.Hour {
        return cached, nil
    }

    // Fetch VCEK (chip-specific)
    vcekURL := fmt.Sprintf("%s/vcek/v1/Milan/%s?tcb=%s", k.baseURL, chipIDHex, tcbVersion)
    vcek, err := k.fetchCertificate(vcekURL)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch VCEK: %w", err)
    }

    // Fetch ASK + ARK chain
    certChainURL := fmt.Sprintf("%s/vcek/v1/Milan/cert_chain", k.baseURL)
    certChain, err := k.fetchCertificate(certChainURL)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch cert chain: %w", err)
    }

    // Parse ASK and ARK from chain
    ask, ark, err := parseCertChain(certChain)
    if err != nil {
        return nil, err
    }

    chain := &CachedCertChain{
        VCEK:      vcek,
        ASK:       ask,
        ARK:       ark,
        FetchedAt: time.Now(),
    }

    // Cache for 24 hours
    k.certCacheMutex.Lock()
    k.certCache[chipIDHex] = chain
    k.certCacheMutex.Unlock()

    return chain, nil
}
```

**Integration into Verifier:**
```go
// pkg/policy/verifier.go
func (v *Verifier) verifyCertificateChain(evidence *attestation.AttestationEvidence) CheckResult {
    // If certificates not in evidence, fetch from AMD KDS
    if len(evidence.Certificates) == 0 && v.kdsClient != nil {
        chain, err := v.kdsClient.FetchCertificateChain(
            evidence.Report.ChipID,
            evidence.Report.GetTCBVersion(),
        )
        if err != nil {
            return CheckResult{Passed: false, Message: fmt.Sprintf("KDS fetch failed: %v", err)}
        }
        evidence.Certificates = [][]byte{chain.VCEK, chain.ASK, chain.ARK}
    }

    // Verify signature chain
    return v.verifySignatureChain(evidence.Certificates)
}
```

---

### 3.2 CoRIM Support (Reference Value Distribution)

**Objective:** Implement IETF draft-ietf-rats-corim for distributing reference measurements

**What is CoRIM?**
- **CoRIM** = Concise Reference Integrity Manifest
- IETF standard (draft) for packaging and distributing reference values
- Replaces manual YAML configuration with signed manifests
- Enables automated CI/CD integration

**CoRIM Structure:**
```json
{
  "corim-id": "urn:uuid:12345678-1234-5678-1234-567812345678",
  "profile": "https://amd.com/sev-snp/v1",
  "validity": {
    "not-before": "2025-01-14T00:00:00Z",
    "not-after": "2025-04-14T00:00:00Z"
  },
  "entities": [
    {
      "name": "CockroachDB Attested TLS Proxy Team",
      "roles": ["manifest-creator", "tag-creator"]
    }
  ],
  "tags": [
    {
      "tag-id": "atls-proxy-v1.0-gcp-ubuntu2204",
      "environment": {
        "class": {
          "vendor": "GCP",
          "model": "n2d-standard-2",
          "instance-id": "ubuntu-2204-jammy-v20250114"
        }
      },
      "measurement-values": [
        {
          "svn": 1,
          "digests": [
            {
              "alg-id": "sha-384",
              "value": "544553545f4d4541535552454d454e545f56414c49445f303031..."
            }
          ],
          "flags": {
            "debug-disabled": true,
            "smt-disabled": true
          }
        }
      ]
    }
  ],
  "signature": {
    "alg": "ES384",
    "value": "base64-encoded-signature..."
  }
}
```

**File:** `pkg/corim/client.go`
```go
package corim

import (
    "encoding/json"
    "fmt"
    "net/http"
)

type CoRIMClient struct {
    repositoryURL string  // https://mycompany.com/.well-known/corim
    httpClient    *http.Client
}

type CoRIM struct {
    CorimID  string                 `json:"corim-id"`
    Profile  string                 `json:"profile"`
    Validity CoRIMValidity          `json:"validity"`
    Tags     []CoRIMTag             `json:"tags"`
}

type CoRIMTag struct {
    TagID             string                  `json:"tag-id"`
    MeasurementValues []CoRIMMeasurementValue `json:"measurement-values"`
}

type CoRIMMeasurementValue struct {
    SVN     int                    `json:"svn"`
    Digests []CoRIMDigest          `json:"digests"`
    Flags   map[string]bool        `json:"flags"`
}

type CoRIMDigest struct {
    AlgID string `json:"alg-id"`
    Value string `json:"value"`
}

// FetchCoRIM downloads and parses CoRIM manifest
func (c *CoRIMClient) FetchCoRIM(appVersion string) (*CoRIM, error) {
    url := fmt.Sprintf("%s/atls-proxy-%s.corim", c.repositoryURL, appVersion)
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var corim CoRIM
    if err := json.NewDecoder(resp.Body).Decode(&corim); err != nil {
        return nil, err
    }

    // TODO: Verify CoRIM signature
    if err := c.verifySignature(&corim); err != nil {
        return nil, fmt.Errorf("invalid CoRIM signature: %w", err)
    }

    return &corim, nil
}

// ExtractMeasurements gets all acceptable measurements from CoRIM
func (c *CoRIM) ExtractMeasurements() []string {
    var measurements []string
    for _, tag := range c.Tags {
        for _, mv := range tag.MeasurementValues {
            for _, digest := range mv.Digests {
                if digest.AlgID == "sha-384" {
                    measurements = append(measurements, digest.Value)
                }
            }
        }
    }
    return measurements
}
```

**Integration into Verifier:**
```go
// pkg/policy/verifier.go
func NewVerifier(policy *Policy) (*Verifier, error) {
    v := &Verifier{policy: policy}

    // If CoRIM repository configured, fetch reference values
    if policy.CoRIM.Enabled {
        corimClient := corim.NewCoRIMClient(policy.CoRIM.RepositoryURL)
        corimData, err := corimClient.FetchCoRIM(policy.CoRIM.AppVersion)
        if err != nil {
            return nil, fmt.Errorf("failed to fetch CoRIM: %w", err)
        }

        // Extract measurements and update policy
        measurements := corimData.ExtractMeasurements()
        v.policy.Measurements.AllowList = append(v.policy.Measurements.AllowList, measurements...)

        log.Info().
            Int("count", len(measurements)).
            Str("source", "corim").
            Msg("Loaded reference values from CoRIM")
    }

    return v, nil
}
```

**Configuration Update:**
```yaml
# config/attestation-policy.yaml
corim:
  enabled: true
  repository_url: "https://mycompany.com/.well-known/corim"
  app_version: "v1.0"
  refresh_interval: "1h"  # Re-fetch CoRIM periodically

measurements:
  # Local fallback (used if CoRIM unavailable)
  allow_list:
    - "FALLBACK_MEASUREMENT_1"
  mode: "strict"
```

**CI/CD Integration:**
```bash
# .github/workflows/build-sev-snp.yml
- name: Extract SEV-SNP Measurement
  run: |
    MEASUREMENT=$(sudo dmesg | grep "SEV-SNP: measurement" | cut -d: -f2)
    echo "measurement=$MEASUREMENT" >> $GITHUB_ENV

- name: Generate CoRIM Manifest
  run: |
    go run cmd/corim-gen/main.go \
      --app-version=${{ github.ref_name }} \
      --measurement=${{ env.measurement }} \
      --output=atls-proxy-${{ github.ref_name }}.corim

- name: Sign CoRIM
  run: |
    cocli sign \
      --key=${{ secrets.CORIM_SIGNING_KEY }} \
      --in=atls-proxy-${{ github.ref_name }}.corim \
      --out=atls-proxy-${{ github.ref_name }}.signed.corim

- name: Upload to CoRIM Repository
  run: |
    curl -X POST https://mycompany.com/.well-known/corim/upload \
      -H "Authorization: Bearer ${{ secrets.CORIM_UPLOAD_TOKEN }}" \
      --data-binary @atls-proxy-${{ github.ref_name }}.signed.corim
```

---

### 3.3 External Verifier Support (Veraison, Azure Attestation)

**Objective:** Add option to delegate verification to external attestation services

**File:** `pkg/policy/external_verifier.go`
```go
package policy

type ExternalVerifier struct {
    endpoint   string
    httpClient *http.Client
}

type ExternalVerificationRequest struct {
    Evidence    *attestation.AttestationEvidence `json:"evidence"`
    PolicyID    string                           `json:"policy_id"`
}

type ExternalVerificationResponse struct {
    Allowed      bool                   `json:"allowed"`
    Reason       string                 `json:"reason"`
    Checks       []CheckResult          `json:"checks"`
    TCBVersion   string                 `json:"tcb_version"`
}

// VerifyAttestation sends evidence to external verifier (e.g., Veraison)
func (e *ExternalVerifier) VerifyAttestation(
    evidence *attestation.AttestationEvidence,
    peerCerts []*x509.Certificate,
) (*VerificationResult, error) {

    req := &ExternalVerificationRequest{
        Evidence: evidence,
        PolicyID: e.policyID,
    }

    // POST to external verifier
    resp, err := http.Post(
        fmt.Sprintf("%s/v1/verify", e.endpoint),
        "application/json",
        marshalJSON(req),
    )
    if err != nil {
        return nil, fmt.Errorf("external verifier request failed: %w", err)
    }
    defer resp.Body.Close()

    var result ExternalVerificationResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return &VerificationResult{
        Allowed:      result.Allowed,
        Reason:       result.Reason,
        PassedChecks: result.Checks,
        TCBVersion:   result.TCBVersion,
    }, nil
}
```

**Configuration:**
```yaml
# config/attestation-policy.yaml
verifier:
  type: "external"  # "local" or "external"
  external:
    endpoint: "https://veraison.example.com"
    policy_id: "atls-proxy-policy-v1"
    timeout: "5s"
```

This plan provides a complete roadmap from local development to production deployment with full SEV-SNP attestation.