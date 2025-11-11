# Attestation Implementation Status

## Overview

This document shows exactly where TLS attestation happens in the code and what's implemented vs. what's planned.

## ✅ IMPLEMENTED

### Phase 2.1 - SEV-SNP Attestation
### Phase 2.2 - RFC 9261 Exported Authenticators
### Phase 2.3 - Attestation in X.509 Certificate Extensions

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

### 6. RFC 9261 Exported Authenticators

**File:** `pkg/tls/exported_auth.go` (574 lines)

```go
// Generate authenticator request
func GenerateAuthenticatorRequest(conn *tls.Conn, extensions []Extension) (*AuthenticatorRequest, error) {
    context := make([]byte, 32)
    rand.Read(context)  // Unique per request
    return &AuthenticatorRequest{CertificateRequestContext: context, Extensions: extensions}
}

// Generate authenticator (binds attestation to TLS session)
func GenerateAuthenticator(conn *tls.Conn, request *AuthenticatorRequest,
    cert *x509.Certificate, privateKey crypto.PrivateKey) ([]byte, error) {

    // Build Certificate message
    certMsg := buildCertificateMessage(request.CertificateRequestContext, cert)

    // Export session-specific keys (THIS IS THE KEY BINDING!)
    exportedKey, _ := conn.ConnectionState().ExportKeyingMaterial(
        ExporterLabelAuthenticator, handshakeContext, 32)

    // Sign with exported keys
    certVerify, _ := buildCertificateVerify(privateKey, handshakeContext, exportedKey)
    return encodeAuthenticator(certMsg, certVerify)
}

// Verify authenticator
func VerifyAuthenticator(conn *tls.Conn, request *AuthenticatorRequest,
    authenticatorData []byte) (*Authenticator, error) {

    auth, _ := parseAuthenticator(authenticatorData)
    exportedKey, _ := conn.ConnectionState().ExportKeyingMaterial(...)
    verifyCertificateVerify(auth.Certificate, handshakeContext, exportedKey, auth.CertificateVerify)
    return auth
}
```

**What this does:**
- Implements RFC 9261 post-handshake authentication for TLS 1.3
- Uses `ExportKeyingMaterial()` to derive session-specific secrets
- Cryptographically binds authenticator to specific TLS connection
- Prevents replay attacks across different sessions
- Supports ECDSA P-256/384/521 and RSA-PSS signatures
- Complete TLS wire format encoding/decoding

### 7. Entity Attestation Token (EAT) and X.509 Extensions

**File:** `pkg/tls/attestation_extension.go` (390 lines)

```go
// EAT structure (CBOR-encoded)
type EAT struct {
    Nonce              []byte            `cbor:"10,keyasint"`   // Fresh nonce
    UEID               []byte            `cbor:"256,keyasint"`  // Chip ID
    SecurityLevel      int               `cbor:"261,keyasint"`  // Hardware TEE = 3
    AttestationReport  []byte            `cbor:"1001,keyasint"` // Raw 1184-byte report
    Measurements       map[string][]byte `cbor:"1002,keyasint"` // SHA-384 measurements
    TCBVersion         string            `cbor:"1003,keyasint"` // TCB version
    CertificateChain   [][]byte          `cbor:"1100,keyasint"` // VCEK, ASK, ARK
}

// Create certificate with attestation extension
func CreateCertificateWithAttestation(evidence *AttestationEvidence,
    publicKey crypto.PublicKey, privateKey crypto.PrivateKey,
    subject pkix.Name) (*x509.Certificate, error) {

    // Encode attestation as CBOR EAT
    eat := &EAT{
        Nonce: evidence.Nonce,
        UEID: evidence.Report.ChipID[:],
        SecurityLevel: 3,
        AttestationReport: evidence.Report.Marshal(),
        Measurements: map[string][]byte{"measurement": evidence.Report.Measurement[:]},
        TCBVersion: evidence.Report.GetTCBVersion(),
        CertificateChain: evidence.Certificates,
    }
    eatBytes, _ := cbor.Marshal(eat)

    // Create certificate with attestation extension (OID 1.3.6.1.4.1.99999.1)
    template := &x509.Certificate{
        ExtraExtensions: []pkix.Extension{{
            Id: OIDAttestationExtension,
            Critical: false,
            Value: eatBytes,
        }},
    }

    certDER, _ := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
    return x509.ParseCertificate(certDER)
}

// Extract attestation from certificate
func ExtractAttestationExtension(cert *x509.Certificate) (*AttestationEvidence, error) {
    // Find attestation extension
    var eatBytes []byte
    for _, ext := range cert.Extensions {
        if ext.Id.Equal(OIDAttestationExtension) {
            eatBytes = ext.Value
            break
        }
    }

    // CBOR-decode EAT
    var eat EAT
    cbor.Unmarshal(eatBytes, &eat)

    // Parse attestation report
    report, _ := attestation.ParseReport(eat.AttestationReport)

    // Return reconstructed evidence
    return &AttestationEvidence{
        Report: report,
        Certificates: eat.CertificateChain,
        Nonce: eat.Nonce,
        Timestamp: eat.Timestamp,
    }
}
```

**What this does:**
- Encodes attestation evidence as CBOR EAT (Entity Attestation Token)
- Embeds EAT in X.509 certificate extension (custom OID)
- Includes all SEV-SNP attestation data (report, measurements, TCB, certificates)
- Extracts and validates attestation from peer certificates
- Validates timestamp freshness (±5 minutes)
- Enforces security level (hardware TEE minimum)
- Creates self-signed certificates with 1-day validity
- Supports Certificate Signing Requests (CSRs) with attestation

---

## ❌ NOT YET IMPLEMENTED

### Phase 2.4: Policy Verification Engine

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

### ✅ Implemented (Phases 2.1, 2.2, 2.3):
- **Phase 2.1: SEV-SNP Attestation**
  - SEV-SNP attestation report structures (1184 bytes)
  - CGo bindings to `/dev/sev-guest` ioctl
  - Hardware attestation report generation
  - AMD certificate chain fetching (VCEK, ASK, ARK)
  - Mock attester for testing without hardware

- **Phase 2.2: RFC 9261 Exported Authenticators**
  - Complete RFC 9261 implementation (574 lines)
  - Session-specific key derivation via ExportKeyingMaterial()
  - Cryptographic binding of attestation to TLS session
  - Support for ECDSA P-256/384/521 and RSA-PSS
  - TLS wire format encoding/decoding

- **Phase 2.3: EAT and X.509 Extensions**
  - Entity Attestation Token (EAT) CBOR encoding (390 lines)
  - X.509 certificate extension embedding (custom OID)
  - Complete SEV-SNP attestation data inclusion
  - Timestamp freshness validation
  - Security level enforcement
  - CSR support with attestation

### ❌ Still Needed:
- **Phase 2.4:** Policy verification engine
- **Phase 3:** Integration into proxy handler
- **Phase 3:** OAuth Token Exchange (STS)

### Key Files:
- `pkg/attestation/types.go` (367 lines) - Report structures ✅
- `pkg/attestation/sev_snp.go` (302 lines) - Hardware interface ✅
- `pkg/tls/exported_auth.go` (574 lines) - RFC 9261 ✅
- `pkg/tls/attestation_extension.go` (390 lines) - EAT extension ✅
- `pkg/policy/verifier.go` - Verification logic ❌
- `pkg/backend/proxy.go` - Needs attestation integration ❌

### Next Steps:
1. Implement `pkg/policy/verifier.go` (AMD signature chain verification, measurement comparison)
2. Update `pkg/backend/proxy.go` to extract and verify attestation before forwarding
3. Implement OAuth Token Exchange (Phase 3)

**Current State:** We can now GET attestation from hardware, ENCODE it in certificates, and BIND it to TLS sessions. We still need to VERIFY attestation and INTEGRATE into the proxy handler.