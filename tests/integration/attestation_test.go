package integration

import (
	"testing"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/tests/integration/helpers"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/tests/integration/testclient"
)

// TestValidAttestation tests that a client with valid attestation can connect
func TestValidAttestation(t *testing.T) {
	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment
	env := helpers.SetupTestEnv(t, policyPath)
	defer env.Cleanup()

	// Create valid attestation evidence
	evidence, err := testclient.DefaultValidEvidence()
	if err != nil {
		t.Fatalf("Failed to create valid evidence: %v", err)
	}

	// Generate certificate with attestation
	err = env.Client.GenerateCertificate(evidence)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Try to connect
	conn, err := env.Client.Connect(env.Proxy.GetAddr())
	if err != nil {
		t.Fatalf("Failed to connect with valid attestation: %v", err)
	}
	defer conn.Close()

	t.Log("Successfully connected with valid attestation")
}

// TestInvalidMeasurement tests that a client with invalid measurement is rejected
func TestInvalidMeasurement(t *testing.T) {
	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment
	env := helpers.SetupTestEnv(t, policyPath)
	defer env.Cleanup()

	// Create evidence with invalid measurement
	evidence, err := testclient.WithInvalidMeasurement()
	if err != nil {
		t.Fatalf("Failed to create invalid measurement evidence: %v", err)
	}

	// Generate certificate with attestation
	err = env.Client.GenerateCertificate(evidence)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Try to connect - TLS dial might succeed but I/O should trigger handshake failure
	conn, err := env.Client.Connect(env.Proxy.GetAddr())
	if err != nil {
		t.Logf("Connection correctly rejected during dial: %v", err)
		return
	}
	defer conn.Close()

	// If dial succeeded, try I/O to trigger handshake - should fail
	_, err = conn.Write([]byte("test"))
	if err != nil {
		t.Logf("Connection correctly rejected during write: %v", err)
		return
	}

	// If write succeeded, try read - should fail
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil {
		t.Logf("Connection correctly rejected during read: %v", err)
		return
	}

	t.Fatal("Expected connection to fail with invalid measurement, but all operations succeeded")
}

// TestDebugEnabled tests behavior when debug mode is enabled
func TestDebugEnabled(t *testing.T) {
	t.Run("strict_policy_rejects_debug", func(t *testing.T) {
		// Get strict policy path
		policyPath := helpers.GetPolicyPath("strict-test.yaml")

		// Setup test environment
		env := helpers.SetupTestEnv(t, policyPath)
		defer env.Cleanup()

		// Create evidence with debug enabled
		evidence, err := testclient.WithDebugEnabled()
		if err != nil {
			t.Fatalf("Failed to create debug evidence: %v", err)
		}

		// Generate certificate
		err = env.Client.GenerateCertificate(evidence)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Try to connect - TLS dial might succeed but I/O should trigger handshake failure
		conn, err := env.Client.Connect(env.Proxy.GetAddr())
		if err != nil {
			t.Logf("Connection correctly rejected during dial with debug enabled: %v", err)
			return
		}
		defer conn.Close()

		// Trigger handshake with I/O
		_, err = conn.Write([]byte("test"))
		if err != nil {
			t.Logf("Connection correctly rejected during write with debug enabled: %v", err)
			return
		}

		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		if err != nil {
			t.Logf("Connection correctly rejected during read with debug enabled: %v", err)
			return
		}

		t.Fatal("Expected connection to fail with debug enabled in strict mode, but it succeeded")
	})

	t.Run("debug_allowed_policy_accepts_debug", func(t *testing.T) {
		// Get debug-allowed policy path
		policyPath := helpers.GetPolicyPath("debug-allowed-test.yaml")

		// Setup test environment
		env := helpers.SetupTestEnv(t, policyPath)
		defer env.Cleanup()

		// Create evidence with debug enabled
		evidence, err := testclient.WithDebugEnabled()
		if err != nil {
			t.Fatalf("Failed to create debug evidence: %v", err)
		}

		// Generate certificate
		err = env.Client.GenerateCertificate(evidence)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Try to connect - should succeed with debug-allowed policy
		conn, err := env.Client.Connect(env.Proxy.GetAddr())
		if err != nil {
			t.Fatalf("Failed to connect with debug-allowed policy: %v", err)
		}
		defer conn.Close()

		t.Log("Successfully connected with debug enabled using debug-allowed policy")
	})
}

// TestSMTEnabled tests behavior when SMT is enabled
func TestSMTEnabled(t *testing.T) {
	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment
	env := helpers.SetupTestEnv(t, policyPath)
	defer env.Cleanup()

	// Create evidence with SMT enabled
	evidence, err := testclient.WithSMTEnabled()
	if err != nil {
		t.Fatalf("Failed to create SMT evidence: %v", err)
	}

	// Generate certificate
	err = env.Client.GenerateCertificate(evidence)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Try to connect - TLS dial might succeed but I/O should trigger handshake failure
	conn, err := env.Client.Connect(env.Proxy.GetAddr())
	if err != nil {
		t.Logf("Connection correctly rejected during dial with SMT enabled: %v", err)
		return
	}
	defer conn.Close()

	// Trigger handshake with I/O
	_, err = conn.Write([]byte("test"))
	if err != nil {
		t.Logf("Connection correctly rejected during write with SMT enabled: %v", err)
		return
	}

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil {
		t.Logf("Connection correctly rejected during read with SMT enabled: %v", err)
		return
	}

	t.Fatal("Expected connection to fail with SMT enabled in strict mode, but it succeeded")
}

// TestExpiredNonce tests behavior with expired nonce
func TestExpiredNonce(t *testing.T) {
	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment
	env := helpers.SetupTestEnv(t, policyPath)
	defer env.Cleanup()

	// Create evidence with expired nonce
	evidence, err := testclient.WithExpiredNonce()
	if err != nil {
		t.Fatalf("Failed to create expired nonce evidence: %v", err)
	}

	// Generate certificate
	err = env.Client.GenerateCertificate(evidence)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Try to connect - TLS dial might succeed but I/O should trigger handshake failure
	conn, err := env.Client.Connect(env.Proxy.GetAddr())
	if err != nil {
		t.Logf("Connection correctly rejected during dial with expired nonce: %v", err)
		return
	}
	defer conn.Close()

	// Trigger handshake with I/O
	_, err = conn.Write([]byte("test"))
	if err != nil {
		t.Logf("Connection correctly rejected during write with expired nonce: %v", err)
		return
	}

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil {
		t.Logf("Connection correctly rejected during read with expired nonce: %v", err)
		return
	}

	t.Fatal("Expected connection to fail with expired nonce, but it succeeded")
}

// TestWarnMode tests that warn mode logs violations but allows connections
func TestWarnMode(t *testing.T) {
	// Get warn policy path
	policyPath := helpers.GetPolicyPath("warn-test.yaml")

	// Setup test environment
	env := helpers.SetupTestEnv(t, policyPath)
	defer env.Cleanup()

	// Create evidence with invalid measurement
	evidence, err := testclient.WithInvalidMeasurement()
	if err != nil {
		t.Fatalf("Failed to create invalid measurement evidence: %v", err)
	}

	// Generate certificate
	err = env.Client.GenerateCertificate(evidence)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Try to connect - should succeed in warn mode
	conn, err := env.Client.Connect(env.Proxy.GetAddr())
	if err != nil {
		t.Fatalf("Expected connection to succeed in warn mode, but it failed: %v", err)
	}
	defer conn.Close()

	t.Log("Successfully connected in warn mode despite policy violations")
}

// TestDisabledMode tests that disabled mode allows all connections
func TestDisabledMode(t *testing.T) {
	// Get disabled policy path
	policyPath := helpers.GetPolicyPath("disabled-test.yaml")

	// Setup test environment
	env := helpers.SetupTestEnv(t, policyPath)
	defer env.Cleanup()

	// Create evidence with debug enabled and SMT enabled
	evidence, err := testclient.WithDebugEnabled()
	if err != nil {
		t.Fatalf("Failed to create debug evidence: %v", err)
	}

	// Generate certificate
	err = env.Client.GenerateCertificate(evidence)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Try to connect - should succeed in disabled mode
	conn, err := env.Client.Connect(env.Proxy.GetAddr())
	if err != nil {
		t.Fatalf("Expected connection to succeed in disabled mode, but it failed: %v", err)
	}
	defer conn.Close()

	t.Log("Successfully connected in disabled mode")
}