package integration

import (
	"bufio"
	"fmt"
	"testing"

	"github.com/souravcrl/attested-tls-proxy-cockroach/tests/integration/helpers"
	"github.com/souravcrl/attested-tls-proxy-cockroach/tests/integration/testclient"
)

// TestE2EConnectionForwarding tests that the proxy correctly forwards connections to CRDB after attestation
func TestE2EConnectionForwarding(t *testing.T) {
	// Skip if cockroach binary is not installed
	if !helpers.IsCockroachInstalled() {
		t.Skip("CockroachDB binary not found, skipping E2E test")
	}

	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment with CockroachDB
	env := helpers.SetupTestEnvWithCRDB(t, policyPath)
	defer env.Cleanup()

	t.Logf("CockroachDB started on port %d", env.CRDB.Port)
	t.Logf("Proxy started on port %d", env.Proxy.Port)

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

	// Connect to proxy with attestation
	conn, err := env.Client.Connect(env.Proxy.GetAddr())
	if err != nil {
		t.Fatalf("Failed to connect with valid attestation: %v", err)
	}
	defer conn.Close()

	t.Log("Successfully established attested TLS connection to proxy")

	// Send a simple PostgreSQL protocol message to verify forwarding
	// This is a simplified test - full SQL testing would require more complex setup
	_, err = conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}) // SSLRequest
	if err != nil {
		t.Fatalf("Failed to write to connection: %v", err)
	}

	// Read response from backend through proxy
	reader := bufio.NewReader(conn)
	response := make([]byte, 1)
	_, err = reader.Read(response)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	t.Logf("Received response from backend through proxy: %v", response)
	t.Log("Proxy successfully forwarded connection to CockroachDB backend")
}

// TestE2ERejectedClientCannot Connect tests that clients with invalid attestation cannot connect
func TestE2ERejectedClient(t *testing.T) {
	// Skip if cockroach binary is not installed
	if !helpers.IsCockroachInstalled() {
		t.Skip("CockroachDB binary not found, skipping E2E test")
	}

	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment with CockroachDB
	env := helpers.SetupTestEnvWithCRDB(t, policyPath)
	defer env.Cleanup()

	// Create evidence with invalid measurement
	evidence, err := testclient.WithInvalidMeasurement()
	if err != nil {
		t.Fatalf("Failed to create invalid evidence: %v", err)
	}

	// Generate certificate with attestation
	err = env.Client.GenerateCertificate(evidence)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Try to connect - TLS dial might succeed but I/O should fail
	conn, err := env.Client.Connect(env.Proxy.GetAddr())
	if err != nil {
		t.Logf("Connection correctly rejected during dial: %v", err)
		t.Log("Proxy successfully blocked invalid attestation from reaching backend")
		return
	}
	defer conn.Close()

	// Connection succeeded - try to use it, should fail
	t.Log("TLS dial succeeded, attempting to send data (should fail)")
	_, err = conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}) // SSLRequest
	if err != nil {
		t.Logf("Connection correctly rejected during write: %v", err)
		t.Log("Proxy successfully blocked invalid attestation from reaching backend")
		return
	}

	// Write succeeded - try to read, should fail
	t.Log("Write succeeded, attempting to read (should fail)")
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil {
		t.Logf("Connection correctly rejected during read: %v", err)
		t.Log("Proxy successfully blocked invalid attestation from reaching backend")
		return
	}

	// If we get here, the connection fully succeeded when it shouldn't have
	t.Fatal("Expected connection to fail with invalid attestation, but all operations succeeded")
}

// TestE2EMultipleConnections tests concurrent connections through the proxy
func TestE2EMultipleConnections(t *testing.T) {
	// Skip if cockroach binary is not installed
	if !helpers.IsCockroachInstalled() {
		t.Skip("CockroachDB binary not found, skipping E2E test")
	}

	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment with CockroachDB
	env := helpers.SetupTestEnvWithCRDB(t, policyPath)
	defer env.Cleanup()

	// Number of concurrent connections
	numConns := 5

	// Create a channel to collect results
	results := make(chan error, numConns)

	// Launch multiple connections concurrently
	for i := 0; i < numConns; i++ {
		go func(connID int) {
			// Create new client
			client, err := testclient.NewTestClient()
			if err != nil {
				results <- fmt.Errorf("client %d: %w", connID, err)
				return
			}

			// Create valid attestation
			evidence, err := testclient.DefaultValidEvidence()
			if err != nil {
				results <- fmt.Errorf("client %d: %w", connID, err)
				return
			}

			// Generate certificate
			err = client.GenerateCertificate(evidence)
			if err != nil {
				results <- fmt.Errorf("client %d: %w", connID, err)
				return
			}

			// Connect to proxy
			conn, err := client.Connect(env.Proxy.GetAddr())
			if err != nil {
				results <- fmt.Errorf("client %d: %w", connID, err)
				return
			}
			defer conn.Close()

			// Write a test message
			_, err = conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
			results <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numConns; i++ {
		err := <-results
		if err != nil {
			t.Errorf("Connection %d failed: %v", i, err)
		}
	}

	t.Logf("Successfully handled %d concurrent connections", numConns)
}
