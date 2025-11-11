package integration

import (
	"testing"

	"github.com/souravcrl/attested-tls-proxy-cockroach/tests/integration/helpers"
	"github.com/souravcrl/attested-tls-proxy-cockroach/tests/integration/testclient"
)

// TestE2EBasicQuery tests end-to-end SQL query through the proxy
func TestE2EBasicQuery(t *testing.T) {
	// Skip if cockroach binary is not installed
	if !helpers.IsCockroachInstalled() {
		t.Skip("CockroachDB binary not found, skipping E2E test")
	}

	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment with CockroachDB
	env := helpers.SetupTestEnvWithCRDB(t, policyPath)
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

	// Connect to database through proxy
	clientCfg := &testclient.ClientConfig{
		ServerAddr: env.Proxy.GetAddr(),
		Database:   "defaultdb",
		User:       "root",
	}

	err = env.Client.ConnectDB(clientCfg)
	if err != nil {
		t.Fatalf("Failed to connect to database through proxy: %v", err)
	}

	// Execute a simple query
	var version string
	err = env.Client.QueryRow("SELECT version()").Scan(&version)
	if err != nil {
		t.Fatalf("Failed to query version: %v", err)
	}

	t.Logf("CockroachDB version: %s", version)
}

// TestE2ECreateTableAndInsert tests creating tables and inserting data
func TestE2ECreateTableAndInsert(t *testing.T) {
	// Skip if cockroach binary is not installed
	if !helpers.IsCockroachInstalled() {
		t.Skip("CockroachDB binary not found, skipping E2E test")
	}

	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment with CockroachDB
	env := helpers.SetupTestEnvWithCRDB(t, policyPath)
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

	// Connect to database through proxy
	clientCfg := &testclient.ClientConfig{
		ServerAddr: env.Proxy.GetAddr(),
		Database:   "defaultdb",
		User:       "root",
	}

	err = env.Client.ConnectDB(clientCfg)
	if err != nil {
		t.Fatalf("Failed to connect to database through proxy: %v", err)
	}

	// Create a test table
	_, err = env.Client.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT PRIMARY KEY,
			name STRING,
			email STRING
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert test data
	_, err = env.Client.Exec(`
		INSERT INTO users (id, name, email) VALUES
		(1, 'Alice', 'alice@example.com'),
		(2, 'Bob', 'bob@example.com')
	`)
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}

	// Query the data back
	rows, err := env.Client.Query("SELECT id, name, email FROM users ORDER BY id")
	if err != nil {
		t.Fatalf("Failed to query data: %v", err)
	}
	defer rows.Close()

	// Verify results
	count := 0
	for rows.Next() {
		var id int
		var name, email string
		err := rows.Scan(&id, &name, &email)
		if err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		count++
		t.Logf("User %d: %s <%s>", id, name, email)
	}

	if count != 2 {
		t.Fatalf("Expected 2 rows, got %d", count)
	}

	t.Log("Successfully created table, inserted data, and queried through proxy")
}

// TestE2ERejectedClientCannotQuery tests that rejected clients cannot query
func TestE2ERejectedClientCannotQuery(t *testing.T) {
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

	// Try to connect to database through proxy - should fail
	clientCfg := &testclient.ClientConfig{
		ServerAddr: env.Proxy.GetAddr(),
		Database:   "defaultdb",
		User:       "root",
	}

	err = env.Client.ConnectDB(clientCfg)
	if err == nil {
		t.Fatal("Expected database connection to fail with invalid attestation, but it succeeded")
	}

	t.Logf("Database connection correctly rejected: %v", err)
}

// TestE2EMultipleClients tests concurrent clients through the proxy
func TestE2EMultipleClients(t *testing.T) {
	// Skip if cockroach binary is not installed
	if !helpers.IsCockroachInstalled() {
		t.Skip("CockroachDB binary not found, skipping E2E test")
	}

	// Get policy path
	policyPath := helpers.GetPolicyPath("strict-test.yaml")

	// Setup test environment with CockroachDB
	env := helpers.SetupTestEnvWithCRDB(t, policyPath)
	defer env.Cleanup()

	// Number of concurrent clients
	numClients := 5

	// Create a channel to collect results
	results := make(chan error, numClients)

	// Launch multiple clients concurrently
	for i := 0; i < numClients; i++ {
		go func(clientID int) {
			// Create new client
			client, err := testclient.NewTestClient()
			if err != nil {
				results <- err
				return
			}
			defer client.Close()

			// Create valid attestation
			evidence, err := testclient.DefaultValidEvidence()
			if err != nil {
				results <- err
				return
			}

			// Generate certificate
			err = client.GenerateCertificate(evidence)
			if err != nil {
				results <- err
				return
			}

			// Connect to database
			clientCfg := &testclient.ClientConfig{
				ServerAddr: env.Proxy.GetAddr(),
				Database:   "defaultdb",
				User:       "root",
			}

			err = client.ConnectDB(clientCfg)
			if err != nil {
				results <- err
				return
			}

			// Execute a query
			var result int
			err = client.QueryRow("SELECT 1").Scan(&result)
			results <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numClients; i++ {
		err := <-results
		if err != nil {
			t.Errorf("Client %d failed: %v", i, err)
		}
	}

	t.Logf("Successfully handled %d concurrent clients", numClients)
}