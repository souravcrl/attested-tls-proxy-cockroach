package testclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"math/big"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver for CockroachDB

	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/attestation"
	tlsext "github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/tls"
)

// TestClient is a test client that can connect to the proxy with attestation
type TestClient struct {
	privateKey crypto.PrivateKey
	cert       *x509.Certificate
	tlsCert    *tls.Certificate
	evidence   *attestation.AttestationEvidence
	db         *sql.DB
}

// ClientConfig holds configuration for the test client
type ClientConfig struct {
	ServerAddr string
	Database   string
	User       string
}

// AttestationParams configures the attestation report
type AttestationParams struct {
	Measurement    [48]byte
	DebugEnabled   bool
	SMTEnabled     bool
	TCBVersion     string
	GuestSVN       uint32
	PlatformVersion uint64
	Nonce          []byte
}

// NewTestClient creates a new test client
func NewTestClient() (*TestClient, error) {
	// Generate ECDSA P-384 key pair (common for attestation)
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return &TestClient{
		privateKey: privateKey,
	}, nil
}

// GenerateCertificate generates a self-signed certificate with attestation extension
func (c *TestClient) GenerateCertificate(evidence *attestation.AttestationEvidence) error {
	c.evidence = evidence

	// Get public key
	publicKey := c.privateKey.(*ecdsa.PrivateKey).Public()

	// Create certificate template
	subject := pkix.Name{
		Organization: []string{"Test Client"},
		CommonName:   "test-client",
	}

	// Create certificate with attestation extension
	cert, err := tlsext.CreateCertificateWithAttestation(
		evidence,
		publicKey,
		c.privateKey,
		subject,
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate with attestation: %w", err)
	}

	c.cert = cert

	// Create TLS certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  c.privateKey,
		Leaf:        cert,
	}
	c.tlsCert = tlsCert

	return nil
}

// Connect establishes a TLS connection to the proxy
func (c *TestClient) Connect(addr string) (*tls.Conn, error) {
	if c.tlsCert == nil {
		return nil, fmt.Errorf("certificate not generated, call GenerateCertificate first")
	}

	// TLS configuration for client
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*c.tlsCert},
		InsecureSkipVerify: true, // Skip server cert verification in tests
		MinVersion:         tls.VersionTLS13,
		ServerName:         "localhost",
	}

	// Connect
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	return conn, nil
}

// ConnectDB establishes a database connection through the proxy
// NOTE: This is a simplified implementation for testing.
// In production, you would need a custom PostgreSQL driver that supports
// using a pre-established TLS connection with attestation.
func (c *TestClient) ConnectDB(config *ClientConfig) error {
	if c.tlsCert == nil {
		return fmt.Errorf("certificate not generated, call GenerateCertificate first")
	}

	// For E2E tests, we just verify the TLS connection works
	// Full SQL testing would require a custom PostgreSQL driver
	// that can use our pre-established attested TLS connection
	return fmt.Errorf("ConnectDB: full SQL over attested TLS requires custom driver (use Connect() for TLS tests)")
}

// Query executes a SQL query
func (c *TestClient) Query(query string) (*sql.Rows, error) {
	if c.db == nil {
		return nil, fmt.Errorf("not connected to database")
	}

	return c.db.Query(query)
}

// QueryRow executes a SQL query that returns a single row
func (c *TestClient) QueryRow(query string) *sql.Row {
	if c.db == nil {
		return nil
	}

	return c.db.QueryRow(query)
}

// Exec executes a SQL statement
func (c *TestClient) Exec(query string, args ...interface{}) (sql.Result, error) {
	if c.db == nil {
		return nil, fmt.Errorf("not connected to database")
	}

	return c.db.Exec(query, args...)
}

// Close closes the database connection
func (c *TestClient) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// CreateMockEvidence creates a mock attestation evidence for testing
func CreateMockEvidence(params AttestationParams) (*attestation.AttestationEvidence, error) {
	// Generate nonce if not provided
	nonce := params.Nonce
	if len(nonce) == 0 {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
	}

	// Create mock attestation report
	report := &attestation.AttestationReport{
		Version:         2,
		GuestSVN:        params.GuestSVN,
		Measurement:     params.Measurement,
		PlatformVersion: params.PlatformVersion,
	}

	// Parse and set TCB version if provided
	if params.TCBVersion != "" {
		var major, minor, build int
		_, err := fmt.Sscanf(params.TCBVersion, "%d.%d.%d", &major, &minor, &build)
		if err != nil {
			return nil, fmt.Errorf("invalid TCB version format: %w", err)
		}
		report.CurrentMajor = uint8(major)
		report.CurrentMinor = uint8(minor)
		report.CurrentBuild = uint8(build)
	}

	// Set policy bits for debug and SMT
	policy := uint64(0)
	if params.DebugEnabled {
		policy |= (1 << 19) // Debug bit
	}
	if !params.SMTEnabled {
		policy |= (1 << 16) // SMT disabled bit
	}
	report.Policy = policy

	// Copy nonce to report data
	copy(report.ReportData[:], nonce)

	// Generate random chip ID and signature (mock)
	if _, err := rand.Read(report.ChipID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate chip ID: %w", err)
	}
	if _, err := rand.Read(report.Signature[:]); err != nil {
		return nil, fmt.Errorf("failed to generate signature: %w", err)
	}

	// Create mock certificate chain (empty for testing without verification)
	certificates := [][]byte{}

	evidence := &attestation.AttestationEvidence{
		Report:       report,
		Certificates: certificates,
		Nonce:        nonce,
		Timestamp:    time.Now().Unix(),
	}

	return evidence, nil
}

// DefaultValidEvidence creates a valid evidence for testing
func DefaultValidEvidence() (*attestation.AttestationEvidence, error) {
	// Valid measurement
	var measurement [48]byte
	copy(measurement[:], []byte("TEST_MEASUREMENT_VALID_001"))

	return CreateMockEvidence(AttestationParams{
		Measurement:     measurement,
		DebugEnabled:    false,
		SMTEnabled:      false,
		TCBVersion:      "1.51.0",
		GuestSVN:        1,
		PlatformVersion: 1,
	})
}

// WithDebugEnabled creates evidence with debug enabled
func WithDebugEnabled() (*attestation.AttestationEvidence, error) {
	var measurement [48]byte
	copy(measurement[:], []byte("TEST_MEASUREMENT_DEBUG"))

	return CreateMockEvidence(AttestationParams{
		Measurement:     measurement,
		DebugEnabled:    true,
		SMTEnabled:      false,
		TCBVersion:      "1.51.0",
		GuestSVN:        1,
		PlatformVersion: 1,
	})
}

// WithSMTEnabled creates evidence with SMT enabled
func WithSMTEnabled() (*attestation.AttestationEvidence, error) {
	var measurement [48]byte
	copy(measurement[:], []byte("TEST_MEASUREMENT_SMT"))

	return CreateMockEvidence(AttestationParams{
		Measurement:     measurement,
		DebugEnabled:    false,
		SMTEnabled:      true,
		TCBVersion:      "1.51.0",
		GuestSVN:        1,
		PlatformVersion: 1,
	})
}

// WithInvalidMeasurement creates evidence with invalid measurement
func WithInvalidMeasurement() (*attestation.AttestationEvidence, error) {
	var measurement [48]byte
	copy(measurement[:], []byte("INVALID_MEASUREMENT_HASH"))

	return CreateMockEvidence(AttestationParams{
		Measurement:     measurement,
		DebugEnabled:    false,
		SMTEnabled:      false,
		TCBVersion:      "1.51.0",
		GuestSVN:        1,
		PlatformVersion: 1,
	})
}

// WithExpiredNonce creates evidence with old timestamp
func WithExpiredNonce() (*attestation.AttestationEvidence, error) {
	var measurement [48]byte
	copy(measurement[:], []byte("TEST_MEASUREMENT_VALID_001"))

	evidence, err := CreateMockEvidence(AttestationParams{
		Measurement:     measurement,
		DebugEnabled:    false,
		SMTEnabled:      false,
		TCBVersion:      "1.51.0",
		GuestSVN:        1,
		PlatformVersion: 1,
	})
	if err != nil {
		return nil, err
	}

	// Set timestamp to 10 minutes ago
	evidence.Timestamp = time.Now().Add(-10 * time.Minute).Unix()

	return evidence, nil
}

// GenerateTestCA generates a self-signed CA certificate for testing
func GenerateTestCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA Root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privateKey, nil
}