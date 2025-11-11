package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/attestation"
)

// Entity Attestation Token (EAT) Implementation
// Based on: draft-ietf-rats-eat (Entity Attestation Token)
// Format: CBOR-encoded token containing attestation evidence

// Custom OID for attestation extension
// Format: 1.3.6.1.4.1.{enterprise}.{attestation}
// Using private enterprise number space for now
var (
	// OID for attestation extension (1.3.6.1.4.1.99999.1)
	OIDAttestationExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
)

// EAT (Entity Attestation Token) represents attestation evidence
// Follows EAT specification for TEE attestation
type EAT struct {
	// Standard EAT Claims (CBOR Map)
	Nonce              []byte                       `cbor:"10,keyasint"` // EAT nonce claim
	UEID               []byte                       `cbor:"256,keyasint"` // Unique Entity ID (chip ID)
	SecurityLevel      int                          `cbor:"261,keyasint"` // Security level (hardware = 3)
	SecureBootEnabled  bool                         `cbor:"262,keyasint"` // Secure boot status
	DebugStatus        int                          `cbor:"263,keyasint"` // Debug disabled = 2
	Timestamp          int64                        `cbor:"6,keyasint"`   // Issued at timestamp

	// SEV-SNP Specific Claims
	AttestationReport  []byte                       `cbor:"1001,keyasint"` // Raw 1184-byte report
	Measurements       map[string][]byte            `cbor:"1002,keyasint"` // Measurement hash
	TCBVersion         string                       `cbor:"1003,keyasint"` // Trusted Computing Base version
	PlatformVersion    uint64                       `cbor:"1004,keyasint"` // Platform version
	GuestSVN           uint32                       `cbor:"1005,keyasint"` // Guest Security Version Number
	Policy             uint64                       `cbor:"1006,keyasint"` // Guest policy flags

	// Certificate Chain
	CertificateChain   [][]byte                     `cbor:"1100,keyasint"` // VCEK, ASK, ARK certificates
}

// CreateCertificateWithAttestation creates an X.509 certificate with attestation extension
func CreateCertificateWithAttestation(
	evidence *attestation.AttestationEvidence,
	publicKey crypto.PublicKey,
	privateKey crypto.PrivateKey,
	subject pkix.Name,
) (*x509.Certificate, error) {

	if evidence == nil {
		return nil, fmt.Errorf("nil attestation evidence")
	}

	logger.Log.Debug().
		Int("nonce_len", len(evidence.Nonce)).
		Str("tcb_version", evidence.Report.GetTCBVersion()).
		Msg("Creating certificate with attestation extension")

	// Step 1: Encode attestation evidence as EAT
	eat := &EAT{
		Nonce:              evidence.Nonce,
		UEID:               evidence.Report.ChipID[:],
		SecurityLevel:      3, // Hardware-based TEE
		SecureBootEnabled:  !evidence.Report.IsDebugEnabled(),
		DebugStatus:        getDebugStatus(evidence.Report),
		Timestamp:          evidence.Timestamp,
		AttestationReport:  evidence.Report.Marshal(),
		Measurements: map[string][]byte{
			"measurement": evidence.Report.Measurement[:],
		},
		TCBVersion:      evidence.Report.GetTCBVersion(),
		PlatformVersion: evidence.Report.PlatformVersion,
		GuestSVN:        evidence.Report.GuestSVN,
		Policy:          evidence.Report.Policy,
		CertificateChain: evidence.Certificates,
	}

	// Step 2: CBOR-encode the EAT
	eatBytes, err := cbor.Marshal(eat)
	if err != nil {
		return nil, fmt.Errorf("failed to encode EAT: %w", err)
	}

	logger.Log.Debug().
		Int("eat_size", len(eatBytes)).
		Msg("EAT encoded successfully")

	// Step 3: Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour), // 1 day validity
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		// Add attestation extension
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDAttestationExtension,
				Critical: false, // Non-critical extension
				Value:    eatBytes,
			},
		},
	}

	// Step 4: Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Step 5: Parse and return certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	logger.Log.Info().
		Str("subject", cert.Subject.CommonName).
		Time("not_before", cert.NotBefore).
		Time("not_after", cert.NotAfter).
		Msg("Certificate with attestation created")

	return cert, nil
}

// ExtractAttestationExtension extracts and decodes attestation from a certificate
func ExtractAttestationExtension(cert *x509.Certificate) (*attestation.AttestationEvidence, error) {
	if cert == nil {
		return nil, fmt.Errorf("nil certificate")
	}

	logger.Log.Debug().
		Str("subject", cert.Subject.CommonName).
		Int("extensions", len(cert.Extensions)).
		Msg("Extracting attestation extension")

	// Step 1: Find the attestation extension
	var eatBytes []byte
	found := false

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDAttestationExtension) {
			eatBytes = ext.Value
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("no attestation extension found in certificate")
	}

	logger.Log.Debug().
		Int("eat_size", len(eatBytes)).
		Msg("Attestation extension found")

	// Step 2: CBOR-decode the EAT
	var eat EAT
	err := cbor.Unmarshal(eatBytes, &eat)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EAT: %w", err)
	}

	// Step 3: Parse the attestation report
	report, err := attestation.ParseReport(eat.AttestationReport)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation report: %w", err)
	}

	// Step 4: Reconstruct AttestationEvidence
	evidence := &attestation.AttestationEvidence{
		Report:       report,
		Certificates: eat.CertificateChain,
		Nonce:        eat.Nonce,
		Timestamp:    eat.Timestamp,
	}

	logger.Log.Info().
		Str("tcb_version", report.GetTCBVersion()).
		Bool("debug_enabled", report.IsDebugEnabled()).
		Bool("smt_enabled", report.IsSMTEnabled()).
		Msg("Attestation evidence extracted from certificate")

	return evidence, nil
}

// CreateCertificateRequest creates a CSR with attestation extension
func CreateCertificateRequest(
	evidence *attestation.AttestationEvidence,
	privateKey crypto.PrivateKey,
	subject pkix.Name,
) (*x509.CertificateRequest, error) {

	if evidence == nil {
		return nil, fmt.Errorf("nil attestation evidence")
	}

	logger.Log.Debug().
		Str("subject", subject.CommonName).
		Msg("Creating CSR with attestation extension")

	// Encode attestation as EAT
	eat := &EAT{
		Nonce:              evidence.Nonce,
		UEID:               evidence.Report.ChipID[:],
		SecurityLevel:      3,
		SecureBootEnabled:  !evidence.Report.IsDebugEnabled(),
		DebugStatus:        getDebugStatus(evidence.Report),
		Timestamp:          evidence.Timestamp,
		AttestationReport:  evidence.Report.Marshal(),
		Measurements: map[string][]byte{
			"measurement": evidence.Report.Measurement[:],
		},
		TCBVersion:      evidence.Report.GetTCBVersion(),
		PlatformVersion: evidence.Report.PlatformVersion,
		GuestSVN:        evidence.Report.GuestSVN,
		Policy:          evidence.Report.Policy,
		CertificateChain: evidence.Certificates,
	}

	eatBytes, err := cbor.Marshal(eat)
	if err != nil {
		return nil, fmt.Errorf("failed to encode EAT: %w", err)
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: subject,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDAttestationExtension,
				Value: eatBytes,
			},
		},
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Parse and return CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	logger.Log.Info().
		Str("subject", csr.Subject.CommonName).
		Msg("CSR with attestation created")

	return csr, nil
}

// ValidateEAT performs basic validation of an EAT token
func ValidateEAT(eat *EAT) error {
	// Check required fields
	if len(eat.Nonce) == 0 {
		return fmt.Errorf("missing nonce in EAT")
	}

	if len(eat.UEID) == 0 {
		return fmt.Errorf("missing UEID in EAT")
	}

	if len(eat.AttestationReport) != attestation.ReportSize {
		return fmt.Errorf("invalid attestation report size: got %d, expected %d",
			len(eat.AttestationReport), attestation.ReportSize)
	}

	// Check security level
	if eat.SecurityLevel < 3 {
		return fmt.Errorf("insufficient security level: %d (expected >= 3)", eat.SecurityLevel)
	}

	// Check debug status
	if eat.DebugStatus != 2 && eat.DebugStatus != 3 {
		// 2 = disabled, 3 = disabled-permanently
		logger.Log.Warn().
			Int("debug_status", eat.DebugStatus).
			Msg("Unexpected debug status in EAT")
	}

	// Check timestamp freshness (within 5 minutes)
	now := time.Now().Unix()
	if eat.Timestamp > now+300 || eat.Timestamp < now-300 {
		return fmt.Errorf("EAT timestamp out of acceptable range: %d (now: %d)", eat.Timestamp, now)
	}

	logger.Log.Debug().
		Int("security_level", eat.SecurityLevel).
		Int("debug_status", eat.DebugStatus).
		Str("tcb_version", eat.TCBVersion).
		Msg("EAT validation passed")

	return nil
}

// getDebugStatus converts attestation report debug status to EAT debug status
func getDebugStatus(report *attestation.AttestationReport) int {
	// EAT debug status values:
	// 0 = enabled
	// 1 = disabled-since-boot
	// 2 = disabled
	// 3 = disabled-permanently
	// 4 = disabled-fully-and-permanently

	if report.IsDebugEnabled() {
		return 0 // Enabled
	}

	// Check policy bits to determine permanence
	// For now, treat all disabled as "disabled" (2)
	return 2
}

// SerializeEAT serializes an EAT to CBOR bytes
func SerializeEAT(eat *EAT) ([]byte, error) {
	return cbor.Marshal(eat)
}

// DeserializeEAT deserializes CBOR bytes to an EAT
func DeserializeEAT(data []byte) (*EAT, error) {
	var eat EAT
	err := cbor.Unmarshal(data, &eat)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal EAT: %w", err)
	}
	return &eat, nil
}

// GenerateTestCertificate generates a simple test certificate for TLS server use
// Returns PEM-encoded certificate and private key
func GenerateTestCertificate(hostname string) ([]byte, []byte, error) {
	// This is used for the proxy server's TLS certificate, not client attestation
	// Generate ECDSA P-256 key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Proxy"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add DNS name if it's a hostname
	if hostname != "" {
		template.DNSNames = []string{hostname}
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	return certPEM, keyPEM, nil
}