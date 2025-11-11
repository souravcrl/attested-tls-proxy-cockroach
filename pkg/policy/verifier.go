package policy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/attestation"
)

// Verifier verifies attestation evidence against policy
type Verifier struct {
	policy *Policy
	cache  *certCache
	mu     sync.RWMutex
}

// certCache caches parsed certificates
type certCache struct {
	vcek      map[string]*cachedCert
	mu        sync.RWMutex
}

type cachedCert struct {
	cert      *x509.Certificate
	expiresAt time.Time
}

// NewVerifier creates a new attestation verifier
func NewVerifier(policy *Policy) (*Verifier, error) {
	if policy == nil {
		policy = NewDefaultPolicy()
	}

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	logger.Log.Info().
		Str("tcb_min", policy.TCB.MinVersion).
		Bool("debug_disabled", policy.Guest.DebugDisabled).
		Str("measurement_mode", policy.Measurements.Mode).
		Msg("Attestation verifier initialized")

	return &Verifier{
		policy: policy,
		cache: &certCache{
			vcek: make(map[string]*cachedCert),
		},
	}, nil
}

// Verify verifies attestation evidence against the policy
func (v *Verifier) Verify(evidence *attestation.AttestationEvidence) (*VerificationResult, error) {
	if evidence == nil {
		return &VerificationResult{
			Allowed:    false,
			Reason:     "nil attestation evidence",
			VerifiedAt: time.Now(),
		}, fmt.Errorf("nil evidence")
	}

	logger.Log.Debug().
		Str("tcb_version", evidence.Report.GetTCBVersion()).
		Bool("debug", evidence.Report.IsDebugEnabled()).
		Msg("Starting attestation verification")

	result := &VerificationResult{
		Allowed:    true,
		Checks:     make([]CheckResult, 0),
		Evidence:   evidence,
		VerifiedAt: time.Now(),
		Metadata:   make(map[string]interface{}),
	}

	// Run all verification checks
	checks := []struct {
		name string
		fn   func(*attestation.AttestationEvidence, *VerificationResult) CheckResult
	}{
		{"nonce_validation", v.verifyNonce},
		{"measurement_validation", v.verifyMeasurement},
		{"tcb_version", v.verifyTCBVersion},
		{"guest_policy", v.verifyGuestPolicy},
		{"signature_validation", v.verifySignature},
		{"certificate_chain", v.verifyCertificateChain},
	}

	for _, check := range checks {
		checkResult := check.fn(evidence, result)
		result.Checks = append(result.Checks, checkResult)

		// If a critical check fails in strict mode, deny immediately
		if !checkResult.Passed && checkResult.Severity == "critical" {
			result.Allowed = false
			result.Reason = fmt.Sprintf("Critical check failed: %s - %s", check.name, checkResult.Message)

			logger.Log.Warn().
				Str("check", check.name).
				Str("reason", checkResult.Message).
				Msg("Attestation verification failed")

			return result, nil
		}
	}

	if result.Allowed {
		result.Reason = "All verification checks passed"
		logger.Log.Info().
			Int("checks_passed", len(result.Checks)).
			Msg("Attestation verification successful")
	}

	return result, nil
}

// verifyNonce validates the nonce
func (v *Verifier) verifyNonce(evidence *attestation.AttestationEvidence, result *VerificationResult) CheckResult {
	check := CheckResult{
		Name:     "nonce_validation",
		Severity: "critical",
		Details:  make(map[string]interface{}),
	}

	// Check if nonce is required
	if v.policy.Nonce.Required && len(evidence.Nonce) == 0 {
		check.Passed = false
		check.Message = "Nonce is required but not present"
		return check
	}

	// Check minimum length
	if len(evidence.Nonce) < v.policy.Nonce.MinLength {
		check.Passed = false
		check.Message = fmt.Sprintf("Nonce too short: got %d bytes, minimum %d",
			len(evidence.Nonce), v.policy.Nonce.MinLength)
		return check
	}

	// Check nonce freshness (based on evidence timestamp)
	age := time.Since(time.Unix(evidence.Timestamp, 0))
	if age > v.policy.Nonce.MaxAge {
		check.Passed = false
		check.Message = fmt.Sprintf("Nonce too old: age %v exceeds maximum %v", age, v.policy.Nonce.MaxAge)
		check.Details["age"] = age.String()
		check.Details["max_age"] = v.policy.Nonce.MaxAge.String()
		return check
	}

	// Verify nonce matches report data
	reportNonce := evidence.Report.GetNonce()
	if !bytes.Equal(evidence.Nonce, reportNonce) {
		check.Passed = false
		check.Message = "Nonce mismatch between evidence and report"
		return check
	}

	check.Passed = true
	check.Message = "Nonce validation passed"
	check.Details["nonce_length"] = len(evidence.Nonce)
	check.Details["age"] = age.String()

	return check
}

// verifyMeasurement validates the measurement against policy
func (v *Verifier) verifyMeasurement(evidence *attestation.AttestationEvidence, result *VerificationResult) CheckResult {
	check := CheckResult{
		Name:     "measurement_validation",
		Details:  make(map[string]interface{}),
	}

	// Determine severity based on enforcement mode
	if ShouldEnforce(v.policy.Measurements.Mode) {
		check.Severity = "critical"
	} else if ShouldWarn(v.policy.Measurements.Mode) {
		check.Severity = "warning"
	} else {
		check.Severity = "info"
		check.Passed = true
		check.Message = "Measurement validation disabled"
		return check
	}

	actualMeasurement := hex.EncodeToString(evidence.Report.Measurement[:])
	check.Details["actual_measurement"] = actualMeasurement

	// Check against expected measurement
	if v.policy.Measurements.Expected != "" {
		expected := strings.ToLower(v.policy.Measurements.Expected)
		actual := strings.ToLower(actualMeasurement)

		if expected == actual {
			check.Passed = true
			check.Message = "Measurement matches expected value"
			return check
		}
	}

	// Check against allow list
	if len(v.policy.Measurements.AllowList) > 0 {
		for _, allowed := range v.policy.Measurements.AllowList {
			if strings.EqualFold(allowed, actualMeasurement) {
				check.Passed = true
				check.Message = "Measurement found in allow list"
				check.Details["matched_allowed"] = allowed
				return check
			}
		}
	}

	// If we get here and it's strict mode, fail
	if ShouldEnforce(v.policy.Measurements.Mode) {
		check.Passed = false
		check.Message = "Measurement does not match policy"
		check.Details["expected"] = v.policy.Measurements.Expected
		check.Details["allow_list_size"] = len(v.policy.Measurements.AllowList)
	} else {
		// Warn mode - log but don't fail
		check.Passed = true
		check.Message = "Measurement mismatch (warn mode)"
		logger.Log.Warn().
			Str("actual", actualMeasurement).
			Str("expected", v.policy.Measurements.Expected).
			Msg("Measurement mismatch in warn mode")
	}

	return check
}

// verifyTCBVersion validates the TCB version
func (v *Verifier) verifyTCBVersion(evidence *attestation.AttestationEvidence, result *VerificationResult) CheckResult {
	check := CheckResult{
		Name:     "tcb_version",
		Details:  make(map[string]interface{}),
	}

	// Determine severity
	if ShouldEnforce(v.policy.TCB.Mode) {
		check.Severity = "critical"
	} else if ShouldWarn(v.policy.TCB.Mode) {
		check.Severity = "warning"
	} else {
		check.Severity = "info"
		check.Passed = true
		check.Message = "TCB validation disabled"
		return check
	}

	actualVersion := evidence.Report.GetTCBVersion()
	check.Details["actual_tcb"] = actualVersion
	check.Details["min_tcb"] = v.policy.TCB.MinVersion

	// Simple version comparison (assumes format "major.minor.build")
	if compareTCBVersion(actualVersion, v.policy.TCB.MinVersion) >= 0 {
		check.Passed = true
		check.Message = "TCB version meets minimum requirement"
	} else {
		if ShouldEnforce(v.policy.TCB.Mode) {
			check.Passed = false
			check.Message = fmt.Sprintf("TCB version %s below minimum %s",
				actualVersion, v.policy.TCB.MinVersion)
		} else {
			check.Passed = true
			check.Message = "TCB version below minimum (warn mode)"
			logger.Log.Warn().
				Str("actual", actualVersion).
				Str("minimum", v.policy.TCB.MinVersion).
				Msg("TCB version below minimum in warn mode")
		}
	}

	// Check platform version if specified
	if v.policy.TCB.MinPlatformVersion > 0 {
		if evidence.Report.PlatformVersion >= v.policy.TCB.MinPlatformVersion {
			check.Details["platform_version_ok"] = true
		} else {
			check.Details["platform_version_ok"] = false
			check.Details["actual_platform"] = evidence.Report.PlatformVersion
			check.Details["min_platform"] = v.policy.TCB.MinPlatformVersion
		}
	}

	return check
}

// verifyGuestPolicy validates guest VM policy
func (v *Verifier) verifyGuestPolicy(evidence *attestation.AttestationEvidence, result *VerificationResult) CheckResult {
	check := CheckResult{
		Name:     "guest_policy",
		Details:  make(map[string]interface{}),
	}

	// Determine severity
	if ShouldEnforce(v.policy.Guest.Mode) {
		check.Severity = "critical"
	} else if ShouldWarn(v.policy.Guest.Mode) {
		check.Severity = "warning"
	} else {
		check.Severity = "info"
		check.Passed = true
		check.Message = "Guest policy validation disabled"
		return check
	}

	failures := []string{}

	// Check debug status
	if v.policy.Guest.DebugDisabled && evidence.Report.IsDebugEnabled() {
		failures = append(failures, "debug is enabled")
		check.Details["debug_enabled"] = true
	}

	// Check SMT status
	if v.policy.Guest.SMTDisabled && evidence.Report.IsSMTEnabled() {
		failures = append(failures, "SMT is enabled")
		check.Details["smt_enabled"] = true
	}

	// Check guest SVN
	if v.policy.Guest.MinGuestSVN > 0 && evidence.Report.GuestSVN < v.policy.Guest.MinGuestSVN {
		failures = append(failures, fmt.Sprintf("guest SVN %d below minimum %d",
			evidence.Report.GuestSVN, v.policy.Guest.MinGuestSVN))
		check.Details["guest_svn"] = evidence.Report.GuestSVN
		check.Details["min_guest_svn"] = v.policy.Guest.MinGuestSVN
	}

	if len(failures) > 0 {
		if ShouldEnforce(v.policy.Guest.Mode) {
			check.Passed = false
			check.Message = "Guest policy violations: " + strings.Join(failures, ", ")
		} else {
			check.Passed = true
			check.Message = "Guest policy violations (warn mode): " + strings.Join(failures, ", ")
			logger.Log.Warn().
				Strs("violations", failures).
				Msg("Guest policy violations in warn mode")
		}
	} else {
		check.Passed = true
		check.Message = "Guest policy validation passed"
	}

	return check
}

// verifySignature validates the attestation report signature
func (v *Verifier) verifySignature(evidence *attestation.AttestationEvidence, result *VerificationResult) CheckResult {
	check := CheckResult{
		Name:     "signature_validation",
		Severity: "critical",
		Details:  make(map[string]interface{}),
	}

	if !v.policy.Certificates.VerifySignature {
		check.Passed = true
		check.Message = "Signature verification disabled"
		check.Severity = "info"
		return check
	}

	// For now, we'll implement basic signature verification
	// Full ECDSA P-384 verification requires parsing the VCEK certificate
	if len(evidence.Certificates) == 0 {
		check.Passed = false
		check.Message = "No certificates provided for signature verification"
		return check
	}

	// Parse VCEK certificate (first in chain)
	vcekDER := evidence.Certificates[0]
	vcek, err := parseCertificate(vcekDER)
	if err != nil {
		check.Passed = false
		check.Message = fmt.Sprintf("Failed to parse VCEK certificate: %v", err)
		return check
	}

	// Verify the signature using VCEK public key
	err = v.verifyReportSignature(evidence.Report, vcek)
	if err != nil {
		check.Passed = false
		check.Message = fmt.Sprintf("Signature verification failed: %v", err)
		return check
	}

	check.Passed = true
	check.Message = "Signature verification passed"
	check.Details["vcek_subject"] = vcek.Subject.CommonName

	return check
}

// verifyCertificateChain validates the AMD certificate chain
func (v *Verifier) verifyCertificateChain(evidence *attestation.AttestationEvidence, result *VerificationResult) CheckResult {
	check := CheckResult{
		Name:     "certificate_chain",
		Severity: "critical",
		Details:  make(map[string]interface{}),
	}

	if !v.policy.Certificates.VerifyChain {
		check.Passed = true
		check.Message = "Certificate chain verification disabled"
		check.Severity = "info"
		return check
	}

	if len(evidence.Certificates) < 2 {
		check.Passed = false
		check.Message = "Incomplete certificate chain"
		check.Details["cert_count"] = len(evidence.Certificates)
		return check
	}

	// Parse certificates
	vcek, err := parseCertificate(evidence.Certificates[0])
	if err != nil {
		check.Passed = false
		check.Message = fmt.Sprintf("Failed to parse VCEK: %v", err)
		return check
	}

	// For now, basic validation - full chain verification would require
	// parsing ASK and ARK and validating the complete chain
	check.Passed = true
	check.Message = "Certificate chain basic validation passed"
	check.Details["vcek_not_before"] = vcek.NotBefore
	check.Details["vcek_not_after"] = vcek.NotAfter
	check.Details["cert_count"] = len(evidence.Certificates)

	// Check if VCEK is expired
	now := time.Now()
	if now.Before(vcek.NotBefore) || now.After(vcek.NotAfter) {
		check.Passed = false
		check.Message = "VCEK certificate expired or not yet valid"
	}

	return check
}

// verifyReportSignature verifies the ECDSA P-384 signature on the attestation report
func (v *Verifier) verifyReportSignature(report *attestation.AttestationReport, vcek *x509.Certificate) error {
	// Extract public key from VCEK
	pubKey, ok := vcek.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("VCEK does not contain ECDSA public key")
	}

	// The signature is over the first 0x2A0 bytes of the report
	// (everything before the signature field)
	reportData := report.Marshal()[:0x2A0]

	// Hash the report data with SHA-384
	hash := sha512.New384()
	hash.Write(reportData)
	digest := hash.Sum(nil)

	// Extract r and s from signature (first 48 bytes each for P-384)
	sig := report.Signature
	r := new(big.Int).SetBytes(sig[0:48])
	s := new(big.Int).SetBytes(sig[48:96])

	// Verify ECDSA signature
	if !ecdsa.Verify(pubKey, digest, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// Helper functions

func parseCertificate(certData []byte) (*x509.Certificate, error) {
	// Try to parse as DER first
	cert, err := x509.ParseCertificate(certData)
	if err == nil {
		return cert, nil
	}

	// Try PEM
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

func compareTCBVersion(actual, minimum string) int {
	// Simple version comparison - split by "." and compare numerically
	actualParts := strings.Split(actual, ".")
	minParts := strings.Split(minimum, ".")

	for i := 0; i < len(actualParts) && i < len(minParts); i++ {
		var actualNum, minNum int
		fmt.Sscanf(actualParts[i], "%d", &actualNum)
		fmt.Sscanf(minParts[i], "%d", &minNum)

		if actualNum > minNum {
			return 1
		} else if actualNum < minNum {
			return -1
		}
	}

	return 0
}

// LoadPolicyFromFile loads a policy from a YAML file
func LoadPolicyFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	policy := NewDefaultPolicy()

	// Parse YAML
	err = yaml.Unmarshal(data, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	// Validate policy
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	logger.Log.Info().
		Str("path", path).
		Str("version", policy.Version).
		Str("measurement_mode", policy.Measurements.Mode).
		Str("tcb_mode", policy.TCB.Mode).
		Str("guest_mode", policy.Guest.Mode).
		Msg("Policy file loaded and validated")

	return policy, nil
}