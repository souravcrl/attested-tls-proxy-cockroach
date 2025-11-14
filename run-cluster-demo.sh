#!/bin/bash

# Cluster Demo Script
# Starts 3 CockroachDB nodes, 3 proxies, dashboard, and test clients
# Shows both DENIED (self-generated nonce) and ALLOWED (proxy-provided nonce) clients

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Attested TLS Proxy Cluster Demo ===${NC}"
echo ""

# Store PIDs for cleanup
CRDB_PIDS=()
PROXY_PIDS=()
DASHBOARD_PID=""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Shutting down cluster...${NC}"

    # Kill dashboard
    if [ ! -z "$DASHBOARD_PID" ] && kill -0 $DASHBOARD_PID 2>/dev/null; then
        echo "  Stopping dashboard (PID: $DASHBOARD_PID)..."
        kill $DASHBOARD_PID 2>/dev/null || true
    fi
    pkill -f "cmd/dashboard" 2>/dev/null || true

    # Kill proxies
    for pid in "${PROXY_PIDS[@]}"; do
        if kill -0 $pid 2>/dev/null; then
            echo "  Stopping proxy (PID: $pid)..."
            kill $pid 2>/dev/null || true
        fi
    done
    pkill -f "attested-tls-proxy" 2>/dev/null || true
    pkill -f "cmd/proxy" 2>/dev/null || true

    # Kill CockroachDB nodes gracefully
    for pid_file in cockroach-data/node*.pid; do
        if [ -f "$pid_file" ]; then
            pid=$(cat "$pid_file" 2>/dev/null)
            if [ ! -z "$pid" ] && kill -0 $pid 2>/dev/null; then
                echo "  Stopping CockroachDB node (PID: $pid)..."
                kill -TERM $pid 2>/dev/null || true
            fi
            rm -f "$pid_file"
        fi
    done

    # Fallback: kill any remaining processes
    pkill -f "cockroach start" 2>/dev/null || true
    pkill -f "connect_to_cluster" 2>/dev/null || true
    pkill -f "test_nonce_clients" 2>/dev/null || true

    # Clean up CockroachDB data directories to avoid lock issues
    rm -rf cockroach-data 2>/dev/null || true

    # Clean up old attestation databases
    rm -f /tmp/attestations-node*.db
    rm -f /tmp/atls-proxy-audit-node*.json

    sleep 2
    echo -e "${GREEN}Shutdown complete${NC}"
}

# Trap signals for graceful shutdown
trap cleanup EXIT INT TERM

# Clean any existing processes
echo -e "${YELLOW}Cleaning up any existing processes...${NC}"
cleanup

# Detect environment
echo -e "${GREEN}Detecting environment...${NC}"
if [ -e "/dev/sev-guest" ]; then
    echo "  ✓ SEV-SNP device detected - using real hardware attestation"
    ATTESTATION_MODE="sev-snp"
    export CGO_CFLAGS="-I/usr/include"
    export CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lcrypto"
elif [ "$(uname)" == "Darwin" ]; then
    echo "  ℹ Running on macOS - using mock attestation"
    ATTESTATION_MODE="mock"
    export CGO_CFLAGS="-I/opt/homebrew/Cellar/openssl@3/3.6.0/include"
    export CGO_LDFLAGS="-L/opt/homebrew/Cellar/openssl@3/3.6.0/lib -lcrypto"
else
    echo "  ℹ Running on Linux (no SEV-SNP) - using mock attestation"
    ATTESTATION_MODE="mock"
    export CGO_CFLAGS="-I/usr/include"
    export CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lcrypto"
fi

# Build binaries
echo -e "${GREEN}Building binaries...${NC}"

# Build React dashboard
echo "  Building React dashboard..."
cd dashboard-ui
npm run build || { echo "Failed to build React dashboard"; exit 1; }
cd ..

echo "  Building proxy..."
go build -o attested-tls-proxy ./cmd/proxy || { echo "Failed to build proxy"; exit 1; }

echo -e "${GREEN}✓ Binaries built successfully${NC}"
echo -e "${YELLOW}Attestation mode: $ATTESTATION_MODE${NC}\n"

# Create data directories
mkdir -p cockroach-data/node1
mkdir -p cockroach-data/node2
mkdir -p cockroach-data/node3

echo -e "${GREEN}Step 1: Starting CockroachDB Node 1 (seed node)${NC}"
./cockroach start \
    --insecure \
    --store=cockroach-data/node1 \
    --listen-addr=localhost:26258 \
    --http-addr=localhost:8091 \
    --join=localhost:26258,localhost:26268,localhost:26278 \
    --background \
    --pid-file=cockroach-data/node1.pid

sleep 2

echo -e "${GREEN}Step 2: Starting CockroachDB Node 2${NC}"
./cockroach start \
    --insecure \
    --store=cockroach-data/node2 \
    --listen-addr=localhost:26268 \
    --http-addr=localhost:8092 \
    --join=localhost:26258,localhost:26268,localhost:26278 \
    --background \
    --pid-file=cockroach-data/node2.pid

sleep 2

echo -e "${GREEN}Step 3: Starting CockroachDB Node 3${NC}"
./cockroach start \
    --insecure \
    --store=cockroach-data/node3 \
    --listen-addr=localhost:26278 \
    --http-addr=localhost:8093 \
    --join=localhost:26258,localhost:26268,localhost:26278 \
    --background \
    --pid-file=cockroach-data/node3.pid

sleep 2

echo -e "${GREEN}Step 4: Initializing cluster${NC}"
./cockroach init --insecure --host=localhost:26258 2>&1 | grep -v "cluster has already been initialized" || true

sleep 2

echo -e "${GREEN}Step 5: Starting Proxy Node 1 (port 26257 -> CRDB 26258)${NC}"
./attested-tls-proxy -config config/proxy-node1.yaml > /tmp/proxy1.log 2>&1 &
PROXY1_PID=$!
PROXY_PIDS+=($PROXY1_PID)
echo "Proxy 1 PID: $PROXY1_PID"

sleep 2

echo -e "${GREEN}Step 6: Starting Proxy Node 2 (port 26267 -> CRDB 26268)${NC}"
./attested-tls-proxy -config config/proxy-node2.yaml > /tmp/proxy2.log 2>&1 &
PROXY2_PID=$!
PROXY_PIDS+=($PROXY2_PID)
echo "Proxy 2 PID: $PROXY2_PID"

sleep 2

echo -e "${GREEN}Step 7: Starting Proxy Node 3 (port 26277 -> CRDB 26278)${NC}"
./attested-tls-proxy -config config/proxy-node3.yaml > /tmp/proxy3.log 2>&1 &
PROXY3_PID=$!
PROXY_PIDS+=($PROXY3_PID)
echo "Proxy 3 PID: $PROXY3_PID"

sleep 2

echo -e "${GREEN}Step 8: React Dashboard${NC}"
echo "  Dashboard is served by each proxy's HTTP API server"
echo "  Open http://localhost:8081 to view the dashboard"

sleep 3

echo -e "\n${GREEN}=== Cluster Status ===${NC}"
echo "CockroachDB Nodes:"
echo "  - Node 1: localhost:26258 (Admin UI: http://localhost:8091)"
echo "  - Node 2: localhost:26268 (Admin UI: http://localhost:8092)"
echo "  - Node 3: localhost:26278 (Admin UI: http://localhost:8093)"
echo ""
echo "Attested TLS Proxies (with React Dashboard):"
echo "  - Proxy 1: localhost:26257 -> CRDB localhost:26258 (Dashboard: http://localhost:8081)"
echo "  - Proxy 2: localhost:26267 -> CRDB localhost:26268 (Dashboard: http://localhost:8082)"
echo "  - Proxy 3: localhost:26277 -> CRDB localhost:26278 (Dashboard: http://localhost:8083)"
echo ""
echo -e "${GREEN}Dashboard: ${YELLOW}http://localhost:8081${NC} (or 8082, 8083)"
echo ""

# Wait for services to be ready
echo -e "${GREEN}Waiting for services to be ready...${NC}"
sleep 5

# Check if services are responding
echo -e "${GREEN}Step 9: Verifying services...${NC}"
curl -s http://localhost:8081/api/v1/health > /dev/null && echo "  ✓ Proxy 1 Dashboard & API responding" || echo "  ✗ Proxy 1 not responding"
curl -s http://localhost:8082/api/v1/health > /dev/null && echo "  ✓ Proxy 2 Dashboard & API responding" || echo "  ✗ Proxy 2 not responding"
curl -s http://localhost:8083/api/v1/health > /dev/null && echo "  ✓ Proxy 3 Dashboard & API responding" || echo "  ✗ Proxy 3 not responding"
echo "  ✓ Nonce endpoint available at: http://localhost:8081/api/v1/nonce"
curl -s http://localhost:8081/ > /dev/null && echo "  ✓ React dashboard available at: http://localhost:8081" || echo "  ✗ React dashboard not responding"

echo ""
echo -e "${GREEN}Step 10: Running test clients (showing both DENIED and ALLOWED)...${NC}"
echo "This will create:"
echo "  - 5 clients with self-generated nonces (will be DENIED)"
echo "  - 5 clients fetching nonces from proxy (will be ALLOWED)"
echo ""

# Create test client program
cat > test_nonce_clients.go <<'CLIENTEOF'
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/tests/integration/testclient"
)

func main() {
	proxies := []string{
		"localhost:26257",
		"localhost:26267",
		"localhost:26277",
	}

	log.Println("Running test clients with nonce validation...")
	log.Println("")

	// First 5 clients: Use self-generated nonces (WILL BE DENIED)
	log.Println("=== Part 1: Clients with self-generated nonces (DENIED) ===")
	for i := 1; i <= 5; i++ {
		proxy := proxies[(i-1)%3]
		log.Printf("\n--- Client %d (SELF-NONCE) connecting to %s ---", i, proxy)

		client, err := testclient.NewTestClient()
		if err != nil {
			log.Printf("ERROR: Failed to create client: %v", err)
			continue
		}

		// Generate our own nonce (not from proxy) - will fail validation
		nonce := make([]byte, 32)
		rand.Read(nonce)

		params := testclient.AttestationParams{
			DebugEnabled: false,
			SMTEnabled:   false,
			TCBVersion:   "1.51.0",
			Nonce:        nonce,
		}

		evidence, err := testclient.CreateMockEvidence(params)
		if err != nil {
			log.Printf("ERROR: Failed to create evidence: %v", err)
			client.Close()
			continue
		}

		err = client.GenerateCertificate(evidence)
		if err != nil {
			log.Printf("ERROR: Failed to generate certificate: %v", err)
			client.Close()
			continue
		}

		conn, err := client.Connect(proxy)
		if err != nil {
			log.Printf("ERROR: Connection failed (expected): %v", err)
			client.Close()
			continue
		}

		log.Printf("✓ Connected (proxy accepted connection)")
		data := fmt.Sprintf("Test data from client %d with self-nonce\n", i)
		conn.Write([]byte(data))

		time.Sleep(1 * time.Second)
		conn.Close()
		client.Close()

		time.Sleep(500 * time.Millisecond)
	}

	log.Println("")
	log.Println("=== Part 2: Clients fetching nonces from proxy (ALLOWED) ===")

	// Next 5 clients: Fetch nonces from proxy (WILL BE ALLOWED)
	for i := 6; i <= 10; i++ {
		proxy := proxies[(i-1)%3]
		log.Printf("\n--- Client %d (PROXY-NONCE) connecting to %s ---", i, proxy)

		client, err := testclient.NewTestClient()
		if err != nil {
			log.Printf("ERROR: Failed to create client: %v", err)
			continue
		}

		// Use ConnectWithAttestation which fetches nonce from proxy
		conn, err := client.ConnectWithAttestation(proxy)
		if err != nil {
			log.Printf("ERROR: Connection failed: %v", err)
			client.Close()
			continue
		}

		log.Printf("✓ Connected with valid proxy nonce!")
		data := fmt.Sprintf("Test data from client %d with proxy nonce\n", i)
		conn.Write([]byte(data))

		time.Sleep(1 * time.Second)
		conn.Close()
		client.Close()

		time.Sleep(500 * time.Millisecond)
	}

	log.Println("")
	log.Println("=== All test clients completed! ===")
	log.Println("Check the dashboard to see DENIED and ALLOWED clients")
}
CLIENTEOF

# Run test clients
echo -e "  ${YELLOW}Starting test clients...${NC}"
go run test_nonce_clients.go > /tmp/clients.log 2>&1 &
CLIENT_PID=$!
echo "Test clients PID: $CLIENT_PID"

# Wait for clients to complete
sleep 25
wait $CLIENT_PID 2>/dev/null || true
echo -e "  ${GREEN}✓ Test clients completed${NC}"

echo ""
echo -e "${GREEN}=== Test Complete ===${NC}"
echo ""

# Display attestation statistics
echo -e "${GREEN}Attestation Statistics:${NC}"
if command -v curl &> /dev/null && command -v python3 &> /dev/null; then
    STATS1=$(curl -s http://localhost:8081/api/v1/stats/overview 2>/dev/null | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"{d.get('allowed',0)} allowed, {d.get('denied',0)} denied, {d.get('total_attestations',0)} total\")" 2>/dev/null || echo "unavailable")
    STATS2=$(curl -s http://localhost:8082/api/v1/stats/overview 2>/dev/null | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"{d.get('allowed',0)} allowed, {d.get('denied',0)} denied, {d.get('total_attestations',0)} total\")" 2>/dev/null || echo "unavailable")
    STATS3=$(curl -s http://localhost:8083/api/v1/stats/overview 2>/dev/null | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"{d.get('allowed',0)} allowed, {d.get('denied',0)} denied, {d.get('total_attestations',0)} total\")" 2>/dev/null || echo "unavailable")

    echo "  - Proxy 1: $STATS1"
    echo "  - Proxy 2: $STATS2"
    echo "  - Proxy 3: $STATS3"
fi

echo ""
echo -e "${GREEN}View Results:${NC}"
echo -e "  ${YELLOW}React Dashboard: http://localhost:8081${NC} (or 8082, 8083)"
echo "  You should see:"
echo "    - DENIED clients (self-generated nonce)"
echo "    - ALLOWED clients (proxy-provided nonce)"
echo ""
echo "API Endpoints:"
echo "  - Nonce endpoint: http://localhost:8081/api/v1/nonce"
echo "  - Attestations: http://localhost:8081/api/v1/attestations"
echo "  - Stats: http://localhost:8081/api/v1/stats/overview"
echo ""
echo "CockroachDB Admin UIs:"
echo "  - Node 1: http://localhost:8091"
echo "  - Node 2: http://localhost:8092"
echo "  - Node 3: http://localhost:8093"
echo ""
echo "Logs:"
echo "  - Proxy 1: /tmp/proxy1.log"
echo "  - Proxy 2: /tmp/proxy2.log"
echo "  - Proxy 3: /tmp/proxy3.log"
echo "  - Dashboard: /tmp/dashboard.log"
echo "  - Test Clients: /tmp/clients.log"
echo ""
echo "Databases:"
echo "  - Attestations Node 1: /tmp/attestations-node1.db"
echo "  - Attestations Node 2: /tmp/attestations-node2.db"
echo "  - Attestations Node 3: /tmp/attestations-node3.db"
echo ""
echo -e "${YELLOW}Press Ctrl+C to gracefully stop all services${NC}"
echo ""
echo "To run more test clients:"
echo "  go run test_nonce_clients.go"
echo ""

# Keep script running and wait for signal
while true; do
    sleep 5

    # Check if proxies are still running
    running_proxies=0
    for pid in "${PROXY_PIDS[@]}"; do
        if kill -0 $pid 2>/dev/null; then
            ((running_proxies++))
        fi
    done

    if [ $running_proxies -lt 3 ]; then
        echo -e "\n${RED}One or more proxies stopped unexpectedly!${NC}"
        echo "Proxy logs:"
        tail -10 /tmp/proxy1.log
        tail -10 /tmp/proxy2.log
        tail -10 /tmp/proxy3.log
        break
    fi
done
