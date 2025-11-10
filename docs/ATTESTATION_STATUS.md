# Attestation Implementation Status

## Overview

This document shows exactly where TLS attestation happens in the code and what's implemented vs. what's planned.

## ✅ IMPLEMENTED (Phase 2.1 - SEV-SNP Attestation)

### 1. Attestation Data Structures

**File:** `pkg/attestation/types.go`

```go
// AMD SEV-SNP Attestation Report (1184 bytes)
type AttestationReport struct {
    Version      uint32
    GuestSVN     uint32
    Policy       uint64
    Measurement  [48]byte    // ← KEY FIELD: SHA-384 of running code
    ReportData   [64]byte    // ← Nonce goes here
    Signature    [512]byte   // ← ECDSA P-384 signature
    // ... many more fields
}

// Complete attestation evidence
type AttestationEvidence struct {
    Report       *AttestationReport
    Certificates [][]byte    // VCEK, ASK, ARK chain
    Nonce        []byte
    Timestamp    int64
}
```

**What this does:**
- Defines the complete AMD SEV-SNP report structure
- Parses raw bytes from `/dev/sev-guest`
- Marshals reports back to bytes
- Extracts key information (TCB version, debug mode, SMT status)

### 2. Hardware Attestation (CGo)

**File:** `pkg/attestation/sev_snp.go`

```c
// CGo wrapper for /dev/sev-guest ioctl
static int get_attestation_report(int fd, uint8_t *nonce, ...) {
    struct snp_report_req req;
    struct snp_report_resp resp;

    // Copy user nonce to request
    memcpy(req.report_data, nonce, nonce_len);

    // Call kernel ioctl
    int ret = ioctl(fd, SNP_GET_REPORT, &ioctl_req);

    // Return 1184-byte attestation report
    memcpy(report_out, resp.report, 1184);
}
```

```go
// Go wrapper
func (a *SEVSNPAttester) GetReport(nonce []byte) (*AttestationEvidence, error) {
    // Open /dev/sev-guest
    // Call CGo function above
    // Parse the 1184-byte report
    // Return AttestationEvidence
}
```

**What this does:**
- Opens `/dev/sev-guest` device (SEV-SNP kernel interface)
- Makes ioctl system call to AMD Secure Processor
- AMD SP generates cryptographic proof of:
  - What code is running (measurements)
  - What hardware it's running on (chip ID)
  - Security configuration (debug mode, SMT, etc.)
- Returns signed attestation report

### 3. AMD Certificate Chain Fetching

**File:** `pkg/attestation/sev_snp.go`

```go
func (a *SEVSNPAttester) fetchCertificateChain(chipID [64]byte) ([][]byte, error) {
    // Fetch VCEK (Versioned Chip Endorsement Key)
    vcekURL := "https://kdsintf.amd.com/vcek/v1/Milan/{chipID}"
    vcek := fetchCertificate(vcekURL)

    // Fetch ASK + ARK (AMD Signing Keys)
    askURL := "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
    certChain := fetchCertificate(askURL)

    return [][]byte{vcek, certChain}
}
```

**What this does:**
- Contacts AMD Key Distribution Service (KDS) over HTTPS
- Downloads VCEK certificate (specific to this chip)
- Downloads ASK + ARK certificates (AMD root of trust)
- Returns certificate chain for signature verification

### 4. Mock Attester for Development

**File:** `pkg/attestation/types.go`

```go
type MockAttester struct {
    reports map[string]*AttestationEvidence
}

func (m *MockAttester) GetReport(nonce []byte) (*AttestationEvidence, error) {
    // Create fake report for testing (no real hardware)
    report := &AttestationReport{
        Version: 1,
        Measurement: []byte("MOCK_MEASUREMENT_FOR_TESTING_ONLY"),
    }
    copy(report.ReportData[:], nonce)
    return &AttestationEvidence{Report: report, Nonce: nonce}
}
```

**What this does:**
- Allows testing without SEV-SNP hardware
- Generates fake attestation reports
- Used when `attestation.provider = "simulated"` in config

### 5. Factory Function

**File:** `pkg/attestation/sev_snp.go`

```go
func NewAttester(provider string) (Attester, error) {
    switch provider {
    case "sev-snp":
        return NewSEVSNPAttester()  // Real hardware
    case "simulated":
        return NewMockAttester()     // Fake for testing
    default:
        return nil, fmt.Errorf("unknown provider")
    }
}
```

---

## ❌ NOT YET IMPLEMENTED

### Phase 2.2: TLS Exported Authenticators (RFC 9261)

**Missing File:** `pkg/tls/exported_auth.go`

**What should happen:**
1. Client and proxy establish TLS 1.3 connection
2. After handshake, proxy generates "Exported Authenticator":
   ```go
   // MISSING CODE:
   func GenerateAuthenticator(conn *tls.Conn, attestation *AttestationEvidence) ([]byte, error) {
       // 1. Export session keys using conn.ConnectionState().ExportKeyingMaterial()
       // 2. Create Certificate message containing attestation
       // 3. Sign with session-derived keys
       // 4. Return authenticator bytes
   }
   ```
3. Client verifies the authenticator proves:
   - The attestation is bound to THIS TLS session
   - Cannot be replayed on different connection

**Why this matters:** Without this, attestation isn't cryptographically bound to the TLS session.

### Phase 2.3: Attestation in Certificate Extension

**Missing File:** `pkg/tls/attestation_extension.go`

**What should happen:**
```go
// MISSING CODE:
func CreateCertificateWithAttestation(evidence *AttestationEvidence) (*x509.Certificate, error) {
    // 1. Encode evidence as EAT (Entity Attestation Token) in CBOR
    // 2. Create X.509 certificate with custom extension OID
    // 3. Embed EAT in extension
    // 4. Return certificate for use in TLS handshake
}
```

### Phase 2.4: Policy Verification

**Missing File:** `pkg/policy/verifier.go`

**What should happen:**
```go
// MISSING CODE:
func (v *Verifier) VerifyAttestation(eat *EntityAttestationToken) (*VerificationResult, error) {
    // 1. Verify AMD signature chain (VCEK → ASK → ARK)
    // 2. Verify report signature using VCEK public key (ECDSA P-384)
    // 3. Compare measurements against policy file
    //    Expected: sha384("proxy binary")
    //    Actual: report.Measurement
    // 4. Check nonce freshness (prevent replay)
    // 5. Verify TCB version >= minimum
    // 6. Check guest policy (debug disabled, etc.)
    // 7. Return ALLOW or DENY
}
```

### Phase 3: Integration into Proxy

**Current Code:** `pkg/backend/proxy.go:75`

```go
// CURRENT - NO ATTESTATION:
func (p *Proxy) handleConnection(clientConn net.Conn) {
    backendConn, _ := p.pool.Get()
    io.Copy(backendConn, clientConn)  // Blind forwarding
}
```

**Should Be:**
```go
// NEEDED - WITH ATTESTATION:
func (p *Proxy) handleConnection(clientConn *tls.Conn) {
    // 1. Extract client certificate
    clientCert := clientConn.ConnectionState().PeerCertificates[0]

    // 2. Extract attestation from certificate extension
    eat, err := ExtractAttestationExtension(clientCert)
    if err != nil {
        logger.Error("No attestation", err)
        return  // REJECT
    }

    // 3. Verify attestation
    result := p.verifier.VerifyAttestation(eat)
    if !result.Allowed {
        logger.Error("Attestation failed", result.Reason)
        return  // REJECT
    }

    // 4. Only now forward to backend
    backendConn, _ := p.pool.Get()
    io.Copy(backendConn, clientConn)
}
```

---

## Current Attestation Flow

### What Works Now:

```
┌────────────┐
│  Proxy VM  │
│  (SEV-SNP) │
└─────┬──────┘
      │
      │ 1. Generate nonce
      ├──> nonce := GenerateNonce()
      │
      │ 2. Request attestation
      ├──> attester := NewSEVSNPAttester()
      ├──> evidence := attester.GetReport(nonce)
      │
      │ 3. AMD Secure Processor generates report
      │    [Hardware creates cryptographic proof]
      │
      │ 4. Fetch AMD certificates
      ├──> evidence := attester.GetExtendedReport(nonce)
      │    [Downloads VCEK, ASK, ARK from AMD KDS]
      │
      └──> evidence.Report.Measurement
           [This contains SHA-384 of running code]
```

### What's Missing:

```
┌────────┐                     ┌───────┐                   ┌──────┐
│ Client │                     │ Proxy │                   │ CRDB │
└────┬───┘                     └───┬───┘                   └──────┘
     │                             │
     │ TLS Handshake              │
     ├────────────────────────────>│
     │                             │
     │ [MISSING: Send cert+EAT]   │
     │                             │
     │                             │ [MISSING: Extract EAT]
     │                             │ [MISSING: Verify signature]
     │                             │ [MISSING: Check measurements]
     │                             │ [MISSING: Policy decision]
     │                             │
     │ [MISSING: ALLOW/DENY]      │
     │<─────────────────────────── │
     │                             │
     │ SQL Queries (if allowed)   │
     │────────────────────────────>│───> [CRDB]
```

---

## How to Test What's Implemented

### Test SEV-SNP Attestation (Requires SEV-SNP VM)

```go
package main

import (
    "fmt"
    "github.com/souravcrl/attested-tls-proxy-cockroach/pkg/attestation"
)

func main() {
    // Create real attester (only works on SEV-SNP VM)
    attester, err := attestation.NewSEVSNPAttester()
    if err != nil {
        fmt.Println("Not a SEV-SNP VM:", err)
        return
    }
    defer attester.Close()

    // Generate nonce
    nonce, _ := attestation.GenerateNonce()

    // Get attestation report
    evidence, err := attester.GetExtendedReport(nonce)
    if err != nil {
        panic(err)
    }

    // Inspect the report
    fmt.Println("TCB Version:", evidence.Report.GetTCBVersion())
    fmt.Println("Debug Enabled:", evidence.Report.IsDebugEnabled())
    fmt.Println("SMT Enabled:", evidence.Report.IsSMTEnabled())
    fmt.Printf("Measurement: %x\n", evidence.Report.Measurement)
    fmt.Println("Certificates fetched:", len(evidence.Certificates))
}
```

### Test Mock Attestation (Works Anywhere)

```go
// Create mock attester
attester := attestation.NewMockAttester()

nonce, _ := attestation.GenerateNonce()
evidence, _ := attester.GetReport(nonce)

fmt.Printf("Mock measurement: %s\n", evidence.Report.Measurement)
// Output: MOCK_MEASUREMENT_FOR_TESTING_ONLY
```

---

## Summary

### ✅ Implemented (Phase 2.1):
- SEV-SNP attestation report structures
- CGo bindings to `/dev/sev-guest`
- Hardware attestation report generation
- AMD certificate chain fetching
- Mock attester for testing

### ❌ Still Needed:
- RFC 9261 Exported Authenticators (Phase 2.2)
- EAT encoding in X.509 extensions (Phase 2.3)
- Policy verification engine (Phase 2.4)
- Integration into proxy handler (Phase 3)
- OAuth Token Exchange (Phase 3)

### Key Files:
- `pkg/attestation/types.go` - Report structures ✅
- `pkg/attestation/sev_snp.go` - Hardware interface ✅
- `pkg/tls/exported_auth.go` - RFC 9261 (missing)
- `pkg/tls/attestation_extension.go` - EAT extension (missing)
- `pkg/policy/verifier.go` - Verification logic (missing)
- `pkg/backend/proxy.go` - Needs attestation integration (missing)

### Next Steps:
1. Implement `pkg/tls/exported_auth.go` (RFC 9261)
2. Implement `pkg/policy/verifier.go` (measurement verification)
3. Update `pkg/backend/proxy.go` to verify attestation before forwarding

The foundation is in place - we can now GET attestation reports from hardware. We need to VERIFY them and BIND them to TLS sessions.