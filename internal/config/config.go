package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete proxy configuration
type Config struct {
	Proxy       ProxyConfig       `yaml:"proxy"`
	Attestation AttestationConfig `yaml:"attestation"`
	Tokens      TokensConfig      `yaml:"tokens"`
	Logging     LoggingConfig     `yaml:"logging"`
	Policy      PolicyConfig      `yaml:"policy"`
}

// ProxyConfig defines proxy listener and backend settings
type ProxyConfig struct {
	Listen  string        `yaml:"listen"`
	Backend BackendConfig `yaml:"backend"`
}

// BackendConfig defines CockroachDB backend connection settings
type BackendConfig struct {
	// For connecting to CRDB in same TEE via localhost
	Host       string    `yaml:"host"`
	Port       int       `yaml:"port"`
	UnixSocket string    `yaml:"unix_socket"` // Preferred for same-VM deployment
	TLS        TLSConfig `yaml:"tls"`
}

// TLSConfig defines TLS settings for backend connections
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CACert     string `yaml:"ca_cert"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
}

// AttestationConfig defines SEV-SNP attestation settings
type AttestationConfig struct {
	Provider   string        `yaml:"provider"` // "sev-snp" or "simulated" (dev only)
	PolicyFile string        `yaml:"policy_file"`
	NonceTTL   time.Duration `yaml:"nonce_ttl"`
}

// TokensConfig defines OAuth Token Exchange settings
type TokensConfig struct {
	STSURL      string        `yaml:"sts_url"`
	TokenTTL    time.Duration `yaml:"token_ttl"`
	DPoPEnabled bool          `yaml:"dpop_enabled"`
}

// LoggingConfig defines logging settings
type LoggingConfig struct {
	Level     string `yaml:"level"`
	AuditFile string `yaml:"audit_file"`
}

// PolicyConfig defines attestation policy settings
type PolicyConfig struct {
	RequireFreshAttestation bool          `yaml:"require_fresh_attestation"`
	MaxAttestationAge       time.Duration `yaml:"max_attestation_age"`
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate proxy config
	if c.Proxy.Listen == "" {
		return fmt.Errorf("proxy.listen is required")
	}

	// Backend must have either host:port or unix_socket
	if c.Proxy.Backend.UnixSocket == "" {
		if c.Proxy.Backend.Host == "" {
			return fmt.Errorf("proxy.backend.host or unix_socket is required")
		}
		if c.Proxy.Backend.Port == 0 {
			return fmt.Errorf("proxy.backend.port is required when not using unix_socket")
		}
	}

	// Validate attestation config
	if c.Attestation.Provider == "" {
		return fmt.Errorf("attestation.provider is required")
	}

	if c.Attestation.Provider != "sev-snp" && c.Attestation.Provider != "simulated" {
		return fmt.Errorf("attestation.provider must be 'sev-snp' or 'simulated'")
	}

	// Warn if simulated attestation is used
	if c.Attestation.Provider == "simulated" {
		fmt.Fprintf(os.Stderr, "WARNING: Using simulated attestation - DO NOT USE IN PRODUCTION\n")
	}

	return nil
}