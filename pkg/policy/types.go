package policy

import (
	"time"

	"github.com/souravcrl/attested-tls-proxy-cockroach/pkg/attestation"
)

// Policy defines the attestation verification policy
type Policy struct {
	// Version of the policy format
	Version string `yaml:"version"`

	// Measurements to verify against
	Measurements MeasurementPolicy `yaml:"measurements"`

	// TCB (Trusted Computing Base) requirements
	TCB TCBPolicy `yaml:"tcb"`

	// Guest policy requirements
	Guest GuestPolicy `yaml:"guest"`

	// Nonce validation settings
	Nonce NoncePolicy `yaml:"nonce"`

	// Certificate chain validation
	Certificates CertificatePolicy `yaml:"certificates"`
}

// MeasurementPolicy defines expected measurements
type MeasurementPolicy struct {
	// Expected measurement hash (SHA-384, hex-encoded)
	Expected string `yaml:"expected"`

	// Allow list of acceptable measurements
	AllowList []string `yaml:"allow_list,omitempty"`

	// Enforcement mode: "strict", "warn", "disabled"
	Mode string `yaml:"mode"`
}

// TCBPolicy defines Trusted Computing Base version requirements
type TCBPolicy struct {
	// Minimum TCB version (format: "major.minor.build")
	MinVersion string `yaml:"min_version"`

	// Platform version minimum
	MinPlatformVersion uint64 `yaml:"min_platform_version,omitempty"`

	// Enforcement mode: "strict", "warn", "disabled"
	Mode string `yaml:"mode"`
}

// GuestPolicy defines guest VM policy requirements
type GuestPolicy struct {
	// Debug must be disabled
	DebugDisabled bool `yaml:"debug_disabled"`

	// SMT (Simultaneous Multi-Threading) must be disabled
	SMTDisabled bool `yaml:"smt_disabled"`

	// Minimum guest SVN (Security Version Number)
	MinGuestSVN uint32 `yaml:"min_guest_svn,omitempty"`

	// Enforcement mode: "strict", "warn", "disabled"
	Mode string `yaml:"mode"`
}

// NoncePolicy defines nonce validation requirements
type NoncePolicy struct {
	// Maximum age of nonce (e.g., "5m")
	MaxAge time.Duration `yaml:"max_age"`

	// Require nonce to be present
	Required bool `yaml:"required"`

	// Minimum nonce length in bytes
	MinLength int `yaml:"min_length"`
}

// CertificatePolicy defines certificate chain validation
type CertificatePolicy struct {
	// Verify AMD certificate chain (VCEK → ASK → ARK)
	VerifyChain bool `yaml:"verify_chain"`

	// Verify signature on attestation report
	VerifySignature bool `yaml:"verify_signature"`

	// Trusted AMD ARK certificate paths (PEM format)
	TrustedARKs []string `yaml:"trusted_arks,omitempty"`

	// Allow cached certificates
	AllowCached bool `yaml:"allow_cached"`

	// Cache duration
	CacheDuration time.Duration `yaml:"cache_duration,omitempty"`
}

// VerificationResult contains the result of attestation verification
type VerificationResult struct {
	// Overall result: allowed or denied
	Allowed bool

	// Detailed reason for the decision
	Reason string

	// Individual check results
	Checks []CheckResult

	// Attestation evidence that was verified
	Evidence *attestation.AttestationEvidence

	// Timestamp of verification
	VerifiedAt time.Time

	// Additional metadata
	Metadata map[string]interface{}
}

// CheckResult represents the result of an individual verification check
type CheckResult struct {
	// Name of the check
	Name string

	// Whether the check passed
	Passed bool

	// Severity: "critical", "warning", "info"
	Severity string

	// Detailed message
	Message string

	// Additional details
	Details map[string]interface{}
}

// Default policy values
const (
	DefaultNonceMaxAge      = 5 * time.Minute
	DefaultNonceMinLength   = 16
	DefaultCacheDuration    = 1 * time.Hour
	DefaultEnforcementMode  = "strict"
)

// NewDefaultPolicy creates a policy with secure defaults
func NewDefaultPolicy() *Policy {
	return &Policy{
		Version: "1.0",
		Measurements: MeasurementPolicy{
			Mode: DefaultEnforcementMode,
		},
		TCB: TCBPolicy{
			MinVersion: "1.0.0",
			Mode:       DefaultEnforcementMode,
		},
		Guest: GuestPolicy{
			DebugDisabled: true,
			SMTDisabled:   true,
			Mode:          DefaultEnforcementMode,
		},
		Nonce: NoncePolicy{
			MaxAge:    DefaultNonceMaxAge,
			Required:  true,
			MinLength: DefaultNonceMinLength,
		},
		Certificates: CertificatePolicy{
			VerifyChain:     true,
			VerifySignature: true,
			AllowCached:     true,
			CacheDuration:   DefaultCacheDuration,
		},
	}
}

// Validate checks if the policy is valid
func (p *Policy) Validate() error {
	// Validate measurement policy
	if p.Measurements.Mode == "" {
		p.Measurements.Mode = DefaultEnforcementMode
	}

	// Validate TCB policy
	if p.TCB.Mode == "" {
		p.TCB.Mode = DefaultEnforcementMode
	}

	// Validate guest policy
	if p.Guest.Mode == "" {
		p.Guest.Mode = DefaultEnforcementMode
	}

	// Validate nonce policy
	if p.Nonce.MaxAge == 0 {
		p.Nonce.MaxAge = DefaultNonceMaxAge
	}
	if p.Nonce.MinLength == 0 {
		p.Nonce.MinLength = DefaultNonceMinLength
	}

	// Validate certificate policy
	if p.Certificates.CacheDuration == 0 {
		p.Certificates.CacheDuration = DefaultCacheDuration
	}

	return nil
}

// ShouldEnforce returns true if the given enforcement mode is "strict"
func ShouldEnforce(mode string) bool {
	return mode == "strict" || mode == ""
}

// ShouldWarn returns true if the given enforcement mode is "warn"
func ShouldWarn(mode string) bool {
	return mode == "warn"
}

// IsDisabled returns true if the given enforcement mode is "disabled"
func IsDisabled(mode string) bool {
	return mode == "disabled"
}