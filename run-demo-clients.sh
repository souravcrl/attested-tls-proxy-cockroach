#!/bin/bash

# Run 10 demo clients with attestation against the running cluster

set -e

echo "Running 10 attested TLS clients..."
echo ""

# Build the demo client program
cat > /tmp/demo_clients.go <<'EOF'
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/attestation"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/tests/integration/testclient"
)

func runClient(id int, proxyAddr string, wg *sync.WaitGroup) {
	defer wg.Done()

	log.Printf("Client %d: Starting connection to %s", id, proxyAddr)

	// Create test client
	client, err := testclient.NewTestClient()
	if err != nil {
		log.Printf("Client %d: Failed to create client: %v", id, err)
		return
	}
	defer client.Close()

	// Create simulated attester
	attester := &attestation.SimulatedAttester{}

	// Generate nonce
	nonce := make([]byte, 32)
	rand.Read(nonce)

	// Get attestation evidence
	evidence, err := attester.GenerateAttestation(nonce)
	if err != nil {
		log.Printf("Client %d: Failed to generate attestation: %v", id, err)
		return
	}

	log.Printf("Client %d: Generated attestation with measurement hash: %x...", id, evidence.Report.Measurement[:8])

	// Generate certificate with attestation
	if err := client.GenerateCertificate(evidence); err != nil {
		log.Printf("Client %d: Failed to generate certificate: %v", id, err)
		return
	}

	// Connect to proxy
	conn, err := client.Connect(proxyAddr)
	if err != nil {
		log.Printf("Client %d: Failed to connect: %v", id, err)
		return
	}
	defer conn.Close()

	log.Printf("Client %d: ✓ Connected! TLS handshake successful", id)

	// Send some test data
	testData := fmt.Sprintf("Test data from client %d at %s\n", id, time.Now().Format(time.RFC3339))
	n, err := conn.Write([]byte(testData))
	if err != nil {
		log.Printf("Client %d: Write error: %v", id, err)
		return
	}
	log.Printf("Client %d: Sent %d bytes", id, n)

	// Try to read (may timeout, that's OK for this demo)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil && err != io.EOF {
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			log.Printf("Client %d: Read timeout (expected)", id)
		}
	}

	// Keep connection open briefly to simulate work
	time.Sleep(2 * time.Second)

	log.Printf("Client %d: ✓ Completed successfully", id)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	proxies := []string{
		"localhost:26257",
		"localhost:26267",
		"localhost:26277",
	}

	var wg sync.WaitGroup

	// Run 10 clients distributed across 3 proxies
	for i := 1; i <= 10; i++ {
		proxy := proxies[(i-1)%len(proxies)]
		wg.Add(1)
		go runClient(i, proxy, &wg)
		time.Sleep(500 * time.Millisecond) // Stagger starts
	}

	wg.Wait()
	log.Println("\n=== All clients completed ===")
}
EOF

cd /tmp
export CGO_CFLAGS="-I/opt/homebrew/Cellar/openssl@3/3.5.0/include"
export CGO_LDFLAGS="-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib -lcrypto"

# Set module path
cd /Users/souravsarangi/go/src/github.com/cockroachdb/attested-tls-proxy-cockroach
go run /tmp/demo_clients.go
