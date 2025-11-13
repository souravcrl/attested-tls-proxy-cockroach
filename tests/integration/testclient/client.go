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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
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

// NewAttestedClient creates a test client with automatic attester detection
// Uses SEV-SNP if /dev/sev-guest exists, otherwise uses simulated attestation
func NewAttestedClient() (*TestClient, error) {
	return NewTestClient()
}

// GetAttester automatically detects and returns the appropriate attester
// Returns SEV-SNP attester if /dev/sev-guest exists, otherwise creates mock evidence
func GetAttester() (attestation.Attester, error) {
	// Check if SEV-SNP device exists
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		// SEV-SNP hardware available
		fmt.Println("✓ Detected SEV-SNP hardware (/dev/sev-guest)")
		return attestation.NewSEVSNPAttester()
	}

	// Fall back to mock attestation
	fmt.Println("ℹ Using mock attestation (no /dev/sev-guest found)")
	return nil, nil // Return nil to indicate we should use mock evidence
}

// FetchNonceFromProxy requests a fresh nonce from the proxy's HTTP API
func FetchNonceFromProxy(proxyAPIAddr string) ([]byte, error) {
	// Extract host from address (remove :port if present from TLS address)
	// and build API URL
	host := proxyAPIAddr
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}

	// Try common API port 8081
	apiURL := fmt.Sprintf("http://%s:8081/api/v1/nonce", host)

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce from %s: %w", apiURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nonce request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var nonceResp struct {
		Nonce     string `json:"nonce"`
		ExpiresIn int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
		return nil, fmt.Errorf("failed to decode nonce response: %w", err)
	}

	// Decode hex nonce
	nonce, err := hex.DecodeString(nonceResp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex nonce: %w", err)
	}

	fmt.Printf("✓ Fetched nonce from proxy (%d bytes, expires in %ds)\n", len(nonce), nonceResp.ExpiresIn)

	return nonce, nil
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

// ConnectWithAttestation automatically generates attestation and connects to the proxy
// This is a convenience method that detects the environment and uses the appropriate attester
func (c *TestClient) ConnectWithAttestation(addr string) (*tls.Conn, error) {
	// Get appropriate attester based on environment
	attester, err := GetAttester()
	if err != nil {
		return nil, fmt.Errorf("failed to get attester: %w", err)
	}

	var evidence *attestation.AttestationEvidence
	var nonce []byte

	// Try to fetch nonce from proxy (this enables proper nonce validation)
	nonce, err = FetchNonceFromProxy(addr)
	if err != nil {
		// If we can't fetch nonce, generate our own (will likely fail validation)
		fmt.Printf("⚠ Could not fetch nonce from proxy: %v\n", err)
		fmt.Println("⚠ Generating self-generated nonce (may fail validation)")
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
	}

	if attester != nil {
		// Real SEV-SNP attestation
		defer attester.Close()

		// Get attestation evidence with the nonce
		evidence, err = attester.GetReport(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestation evidence: %w", err)
		}
	} else {
		// Mock attestation for testing
		params := AttestationParams{
			DebugEnabled: true,
			SMTEnabled:   true,
			TCBVersion:   "1.51.0",
			Nonce:        nonce,
		}
		evidence, err = CreateMockEvidence(params)
		if err != nil {
			return nil, fmt.Errorf("failed to create mock evidence: %w", err)
		}
	}

	// Generate certificate with attestation
	if err := c.GenerateCertificate(evidence); err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Connect to proxy
	return c.Connect(addr)
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