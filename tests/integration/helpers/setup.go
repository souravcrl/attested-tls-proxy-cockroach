package helpers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/config"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/tests/integration/testclient"
)

// TestEnv holds the complete test environment
type TestEnv struct {
	CRDB   *TestCRDB
	Proxy  *TestProxy
	Client *testclient.TestClient
	Config *config.Config
	t      *testing.T
}

// SetupTestEnv creates a complete test environment
func SetupTestEnv(t *testing.T, policyFile string) *TestEnv {
	// Create test config
	cfg := CreateTestConfig(policyFile)

	// Start proxy
	proxy, err := StartTestProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	// Create test client
	client, err := testclient.NewTestClient()
	if err != nil {
		proxy.Stop()
		t.Fatalf("Failed to create client: %v", err)
	}

	return &TestEnv{
		Proxy:  proxy,
		Client: client,
		Config: cfg,
		t:      t,
	}
}

// SetupTestEnvWithCRDB creates a complete test environment including CockroachDB
func SetupTestEnvWithCRDB(t *testing.T, policyFile string) *TestEnv {
	// Start CockroachDB
	crdb, err := StartTestCRDB()
	if err != nil {
		t.Fatalf("Failed to start CockroachDB: %v", err)
	}

	// Wait for CRDB to be ready
	if err := WaitForCRDB(crdb, 30); err != nil {
		crdb.Stop()
		t.Fatalf("CockroachDB failed to start: %v", err)
	}

	// Create test config pointing to CRDB
	cfg := CreateTestConfigWithBackend(policyFile, "localhost", crdb.Port)

	// Start proxy
	proxy, err := StartTestProxy(cfg)
	if err != nil {
		crdb.Stop()
		t.Fatalf("Failed to start proxy: %v", err)
	}

	// Create test client
	client, err := testclient.NewTestClient()
	if err != nil {
		proxy.Stop()
		crdb.Stop()
		t.Fatalf("Failed to create client: %v", err)
	}

	return &TestEnv{
		CRDB:   crdb,
		Proxy:  proxy,
		Client: client,
		Config: cfg,
		t:      t,
	}
}

// Cleanup cleans up all resources
func (e *TestEnv) Cleanup() {
	if e.Client != nil {
		e.Client.Close()
	}
	if e.Proxy != nil {
		e.Proxy.Stop()
	}
	if e.CRDB != nil {
		e.CRDB.Stop()
	}
}

// CreateTestConfig creates a test configuration
func CreateTestConfig(policyFile string) *config.Config {
	return CreateTestConfigWithBackend(policyFile, "localhost", 26257)
}

// CreateTestConfigWithBackend creates a test configuration with custom backend
func CreateTestConfigWithBackend(policyFile, backendHost string, backendPort int) *config.Config {
	// Get absolute path to policy file
	absPath, err := filepath.Abs(policyFile)
	if err != nil {
		absPath = policyFile
	}

	return &config.Config{
		Proxy: config.ProxyConfig{
			Listen: "127.0.0.1:0", // Random port
			Backend: config.BackendConfig{
				Host: backendHost,
				Port: backendPort,
				TLS: config.TLSConfig{
					Enabled: false,
				},
			},
		},
		Attestation: config.AttestationConfig{
			Provider:   "simulated",
			PolicyFile: absPath,
		},
		Logging: config.LoggingConfig{
			Level: "debug",
		},
	}
}

// GetTestDataDir returns the path to test data directory
func GetTestDataDir() string {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "fixtures"
	}

	// Navigate to test data directory
	testDataDir := filepath.Join(cwd, "fixtures")
	return testDataDir
}

// GetPolicyPath returns the full path to a policy file
func GetPolicyPath(filename string) string {
	return filepath.Join(GetTestDataDir(), "policies", filename)
}