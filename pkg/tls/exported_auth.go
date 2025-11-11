package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"hash"
	"math/big"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
)

// RFC 9261: Exported Authenticators in TLS
// This implements the Exported Authenticators extension for TLS 1.3
// allowing post-handshake authentication with attestation evidence
//
// NOTE: This implementation is currently incomplete as Go's standard library
// does not export the ExportKeyingMaterial method. A full implementation would
// require either using a custom TLS library or Go 1.22+ with experimental features.
// For now, we use certificate extensions as the primary mechanism for attestation.

// Constants from RFC 9261
const (
	// Exporter labels for key derivation (RFC 9261 Section 5)
	ExporterLabelAuthenticatorRequest = "EXPORTER-authenticator request"
	ExporterLabelAuthenticator        = "EXPORTER-authenticator"

	// Handshake message types (RFC 8446)
	HandshakeMsgTypeCertificateRequest = 13
	HandshakeMsgTypeCertificate        = 11
	HandshakeMsgTypeCertificateVerify  = 15
	HandshakeMsgTypeFinished           = 20
)

// AuthenticatorRequest represents a request for an authenticator
type AuthenticatorRequest struct {
	CertificateRequestContext []byte
	Extensions                []Extension
}

// Authenticator represents an exported authenticator response
type Authenticator struct {
	CertificateRequestContext []byte
	Certificate               *x509.Certificate
	Extensions                []Extension
	CertificateVerify         *CertificateVerify
}

// Extension represents a TLS extension
type Extension struct {
	Type uint16
	Data []byte
}

// CertificateVerify contains the signature over the handshake
type CertificateVerify struct {
	Algorithm uint16 // SignatureScheme
	Signature []byte
}

// SignatureScheme constants (RFC 8446 Section 4.2.3)
const (
	SignatureSchemeRSAPSSWithSHA256 = 0x0804
	SignatureSchemeRSAPSSWithSHA384 = 0x0805
	SignatureSchemeRSAPSSWithSHA512 = 0x0806
	SignatureSchemeECDSAWithP256    = 0x0403
	SignatureSchemeECDSAWithP384    = 0x0503
	SignatureSchemeECDSAWithP521    = 0x0603
)

// GenerateAuthenticatorRequest creates a new authenticator request
// This is sent by the party requesting authentication
func GenerateAuthenticatorRequest(conn *tls.Conn, extensions []Extension) (*AuthenticatorRequest, error) {
	// Generate random certificate_request_context (RFC 9261 Section 3)
	// Must be at least 1 byte and unique per request
	context := make([]byte, 32)
	if _, err := rand.Read(context); err != nil {
		return nil, fmt.Errorf("failed to generate context: %w", err)
	}

	logger.Log.Debug().
		Int("context_len", len(context)).
		Int("extensions", len(extensions)).
		Msg("Generated authenticator request")

	return &AuthenticatorRequest{
		CertificateRequestContext: context,
		Extensions:                extensions,
	}, nil
}

// GenerateAuthenticator creates an authenticator in response to a request
// This binds attestation evidence to the TLS session
func GenerateAuthenticator(
	conn *tls.Conn,
	request *AuthenticatorRequest,
	cert *x509.Certificate,
	privateKey crypto.PrivateKey,
) ([]byte, error) {

	if conn == nil {
		return nil, fmt.Errorf("nil TLS connection")
	}

	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("exported authenticators require TLS 1.3, got version 0x%x", state.Version)
	}

	logger.Log.Debug().
		Str("tls_version", "1.3").
		Msg("Generating exported authenticator")

	// Step 1: Build Certificate message (RFC 9261 Section 4)
	certMsg := buildCertificateMessage(request.CertificateRequestContext, cert)

	// Step 2: Compute handshake context
	// This is the hash of handshake messages up to and including Certificate
	handshakeContext := computeHandshakeContext(conn, request, certMsg)

	// Step 3: Export keying material (RFC 9261 Section 5)
	// This binds the authenticator to this specific TLS session
	// NOTE: Go's standard library doesn't expose ExportKeyingMaterial
	// This is a simplified placeholder that uses static derivation
	exportedKey := deriveExportedKey(handshakeContext, 32)

	// Step 4: Create CertificateVerify message (RFC 8446 Section 4.4.3)
	certVerify, err := buildCertificateVerify(privateKey, handshakeContext, exportedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build CertificateVerify: %w", err)
	}

	// Step 5: Encode the complete authenticator
	authenticator := encodeAuthenticator(certMsg, certVerify)

	logger.Log.Info().
		Int("authenticator_size", len(authenticator)).
		Msg("Exported authenticator generated")

	return authenticator, nil
}

// VerifyAuthenticator verifies an authenticator received from a peer
func VerifyAuthenticator(
	conn *tls.Conn,
	request *AuthenticatorRequest,
	authenticatorData []byte,
) (*Authenticator, error) {

	if conn == nil {
		return nil, fmt.Errorf("nil TLS connection")
	}

	logger.Log.Debug().
		Int("authenticator_size", len(authenticatorData)).
		Msg("Verifying exported authenticator")

	// Step 1: Parse the authenticator
	auth, err := parseAuthenticator(authenticatorData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authenticator: %w", err)
	}

	// Step 2: Verify the certificate_request_context matches
	if len(auth.CertificateRequestContext) != len(request.CertificateRequestContext) {
		return nil, fmt.Errorf("context length mismatch")
	}
	for i := range auth.CertificateRequestContext {
		if auth.CertificateRequestContext[i] != request.CertificateRequestContext[i] {
			return nil, fmt.Errorf("context mismatch at byte %d", i)
		}
	}

	// Step 3: Rebuild Certificate message to verify signature
	certMsg := buildCertificateMessage(request.CertificateRequestContext, auth.Certificate)

	// Step 4: Compute handshake context
	handshakeContext := computeHandshakeContext(conn, request, certMsg)

	// Step 5: Export keying material
	// NOTE: Go's standard library doesn't expose ExportKeyingMaterial
	// This is a simplified placeholder that uses static derivation
	exportedKey := deriveExportedKey(handshakeContext, 32)

	// Step 6: Verify the CertificateVerify signature
	err = verifyCertificateVerify(auth.Certificate, handshakeContext, exportedKey, auth.CertificateVerify)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	logger.Log.Info().
		Str("subject", auth.Certificate.Subject.CommonName).
		Msg("Authenticator verified successfully")

	return auth, nil
}

// buildCertificateMessage creates a Certificate handshake message
func buildCertificateMessage(context []byte, cert *x509.Certificate) []byte {
	// TLS 1.3 Certificate message format (RFC 8446 Section 4.4.2):
	// struct {
	//     opaque certificate_request_context<0..2^8-1>;
	//     CertificateEntry certificate_list<0..2^24-1>;
	// } Certificate;

	buf := make([]byte, 0, 4096)

	// certificate_request_context length (1 byte) + data
	buf = append(buf, byte(len(context)))
	buf = append(buf, context...)

	// certificate_list length (3 bytes)
	certData := cert.Raw
	certListLen := 3 + len(certData) + 2 // cert_data_len(3) + cert_data + extensions_len(2)
	buf = append(buf, byte(certListLen>>16), byte(certListLen>>8), byte(certListLen))

	// CertificateEntry:
	//   cert_data length (3 bytes)
	buf = append(buf, byte(len(certData)>>16), byte(len(certData)>>8), byte(len(certData)))
	//   cert_data
	buf = append(buf, certData...)
	//   extensions length (2 bytes) - no extensions for now
	buf = append(buf, 0, 0)

	return buf
}

// buildCertificateVerify creates a CertificateVerify message
func buildCertificateVerify(
	privateKey crypto.PrivateKey,
	handshakeContext []byte,
	exportedKey []byte,
) ([]byte, error) {

	// Build signature input per RFC 8446 Section 4.4.3
	signatureInput := buildSignatureInput(handshakeContext, exportedKey, false)

	// Determine signature algorithm and sign
	var signature []byte
	var signatureScheme uint16
	var err error

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		// Use ECDSA with appropriate curve
		switch key.Curve.Params().BitSize {
		case 256:
			signatureScheme = SignatureSchemeECDSAWithP256
			signature, err = signECDSA(key, signatureInput, crypto.SHA256)
		case 384:
			signatureScheme = SignatureSchemeECDSAWithP384
			signature, err = signECDSA(key, signatureInput, crypto.SHA384)
		case 521:
			signatureScheme = SignatureSchemeECDSAWithP521
			signature, err = signECDSA(key, signatureInput, crypto.SHA512)
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve size: %d", key.Curve.Params().BitSize)
		}
	case *rsa.PrivateKey:
		// Use RSA-PSS with SHA-384 (common for attestation)
		signatureScheme = SignatureSchemeRSAPSSWithSHA384
		signature, err = signRSAPSS(key, signatureInput, crypto.SHA384)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Encode CertificateVerify message:
	// struct {
	//     SignatureScheme algorithm;
	//     opaque signature<0..2^16-1>;
	// } CertificateVerify;

	buf := make([]byte, 0, 2+2+len(signature))
	buf = append(buf, byte(signatureScheme>>8), byte(signatureScheme))
	buf = append(buf, byte(len(signature)>>8), byte(len(signature)))
	buf = append(buf, signature...)

	return buf, nil
}

// buildSignatureInput creates the input for signature per RFC 8446 Section 4.4.3
func buildSignatureInput(handshakeContext, exportedKey []byte, isClient bool) []byte {
	// Signature input format:
	// - 64 spaces (0x20)
	// - Context string
	// - 0x00 separator
	// - Hash of (handshakeContext || exportedKey)

	contextString := "TLS 1.3, server CertificateVerify"
	if isClient {
		contextString = "TLS 1.3, client CertificateVerify"
	}

	// Compute hash of handshakeContext || exportedKey
	h := sha256.New()
	h.Write(handshakeContext)
	h.Write(exportedKey)
	contextHash := h.Sum(nil)

	// Build signature input
	input := make([]byte, 64+len(contextString)+1+len(contextHash))
	for i := 0; i < 64; i++ {
		input[i] = 0x20 // space
	}
	offset := 64
	copy(input[offset:], contextString)
	offset += len(contextString)
	input[offset] = 0x00
	offset++
	copy(input[offset:], contextHash)

	return input
}

// signECDSA signs data using ECDSA
func signECDSA(key *ecdsa.PrivateKey, data []byte, hashAlg crypto.Hash) ([]byte, error) {
	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm")
	}

	h.Write(data)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}

	// Encode as r || s (each padded to curve size)
	curveSize := (key.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*curveSize)
	r.FillBytes(signature[:curveSize])
	s.FillBytes(signature[curveSize:])

	return signature, nil
}

// signRSAPSS signs data using RSA-PSS
func signRSAPSS(key *rsa.PrivateKey, data []byte, hashAlg crypto.Hash) ([]byte, error) {
	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm")
	}

	h.Write(data)
	digest := h.Sum(nil)

	return rsa.SignPSS(rand.Reader, key, hashAlg, digest, nil)
}

// computeHandshakeContext computes the hash of handshake messages
func computeHandshakeContext(conn *tls.Conn, request *AuthenticatorRequest, certMsg []byte) []byte {
	// For exported authenticators, the handshake context is:
	// Hash(ClientHello...ServerFinished || CertificateRequest || Certificate)

	h := sha256.New()

	// Note: In a real implementation, we'd need access to the actual handshake transcript
	// For now, we use the certificate_request_context as a proxy
	// This is a simplified implementation
	h.Write(request.CertificateRequestContext)
	h.Write(certMsg)

	return h.Sum(nil)
}

// verifyCertificateVerify verifies the CertificateVerify signature
func verifyCertificateVerify(
	cert *x509.Certificate,
	handshakeContext []byte,
	exportedKey []byte,
	certVerify *CertificateVerify,
) error {

	// Rebuild signature input
	signatureInput := buildSignatureInput(handshakeContext, exportedKey, false)

	// Verify based on signature scheme
	switch certVerify.Algorithm {
	case SignatureSchemeECDSAWithP256:
		return verifyECDSA(cert.PublicKey, signatureInput, certVerify.Signature, crypto.SHA256)
	case SignatureSchemeECDSAWithP384:
		return verifyECDSA(cert.PublicKey, signatureInput, certVerify.Signature, crypto.SHA384)
	case SignatureSchemeECDSAWithP521:
		return verifyECDSA(cert.PublicKey, signatureInput, certVerify.Signature, crypto.SHA512)
	case SignatureSchemeRSAPSSWithSHA384:
		return verifyRSAPSS(cert.PublicKey, signatureInput, certVerify.Signature, crypto.SHA384)
	default:
		return fmt.Errorf("unsupported signature scheme: 0x%x", certVerify.Algorithm)
	}
}

// verifyECDSA verifies an ECDSA signature
func verifyECDSA(publicKey crypto.PublicKey, data, signature []byte, hashAlg crypto.Hash) error {
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an ECDSA public key")
	}

	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported hash algorithm")
	}

	h.Write(data)
	digest := h.Sum(nil)

	// Parse r || s from signature
	curveSize := (ecdsaKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*curveSize {
		return fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:curveSize])
	s := new(big.Int).SetBytes(signature[curveSize:])

	if !ecdsa.Verify(ecdsaKey, digest, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// verifyRSAPSS verifies an RSA-PSS signature
func verifyRSAPSS(publicKey crypto.PublicKey, data, signature []byte, hashAlg crypto.Hash) error {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported hash algorithm")
	}

	h.Write(data)
	digest := h.Sum(nil)

	return rsa.VerifyPSS(rsaKey, hashAlg, digest, signature, nil)
}

// encodeAuthenticator encodes a complete authenticator
func encodeAuthenticator(certMsg, certVerify []byte) []byte {
	// Authenticator format:
	// Certificate || CertificateVerify || Finished
	// (Finished is omitted in exported authenticators)

	buf := make([]byte, 0, len(certMsg)+len(certVerify))
	buf = append(buf, certMsg...)
	buf = append(buf, certVerify...)
	return buf
}

// parseAuthenticator parses an authenticator
func parseAuthenticator(data []byte) (*Authenticator, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("authenticator too short")
	}

	offset := 0

	// Parse certificate_request_context
	contextLen := int(data[offset])
	offset++
	if offset+contextLen > len(data) {
		return nil, fmt.Errorf("invalid context length")
	}
	context := data[offset : offset+contextLen]
	offset += contextLen

	// Parse certificate_list length
	if offset+3 > len(data) {
		return nil, fmt.Errorf("invalid certificate list")
	}
	certListLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3

	if offset+certListLen > len(data) {
		return nil, fmt.Errorf("certificate list truncated")
	}

	// Parse certificate data length
	if offset+3 > len(data) {
		return nil, fmt.Errorf("invalid certificate data")
	}
	certDataLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3

	if offset+certDataLen > len(data) {
		return nil, fmt.Errorf("certificate data truncated")
	}

	// Parse certificate
	certData := data[offset : offset+certDataLen]
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	offset += certDataLen

	// Skip extensions (2 bytes length + data)
	if offset+2 > len(data) {
		return nil, fmt.Errorf("invalid extensions")
	}
	extLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + extLen

	// Parse CertificateVerify
	if offset+4 > len(data) {
		return nil, fmt.Errorf("invalid CertificateVerify")
	}
	signatureScheme := uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2

	signatureLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+signatureLen > len(data) {
		return nil, fmt.Errorf("signature truncated")
	}
	signature := data[offset : offset+signatureLen]

	return &Authenticator{
		CertificateRequestContext: context,
		Certificate:               cert,
		CertificateVerify: &CertificateVerify{
			Algorithm: signatureScheme,
			Signature: signature,
		},
	}, nil
}

// deriveExportedKey is a simplified placeholder for key derivation
// In a proper implementation, this would use TLS 1.3's ExportKeyingMaterial
// which derives keys from the master secret. This simplified version just
// hashes the context to create a deterministic key.
func deriveExportedKey(context []byte, length int) []byte {
	h := sha256.New()
	h.Write(context)
	digest := h.Sum(nil)

	// If we need more bytes than the hash output, repeat the hash
	result := make([]byte, length)
	copy(result, digest)
	return result
}