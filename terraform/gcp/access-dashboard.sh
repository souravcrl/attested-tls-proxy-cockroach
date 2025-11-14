#!/bin/bash
# Access remote dashboard locally via SSH tunnel
# This creates a secure SSH tunnel without exposing dashboard to the internet

set -e

echo "========================================="
echo "Remote Dashboard Access via SSH Tunnel"
echo "========================================="
echo ""

# Check if Terraform has been applied
if [ ! -f "deployment-info.json" ]; then
    echo "ERROR: No deployment found"
    echo "Run: ./deploy.sh first"
    exit 1
fi

# Get instance details
INSTANCE_NAME=$(terraform output -raw instance_name 2>/dev/null)
ZONE=$(terraform output -raw instance_zone 2>/dev/null || echo "us-central1-a")
EXTERNAL_IP=$(terraform output -raw external_ip 2>/dev/null)

if [ -z "$INSTANCE_NAME" ]; then
    echo "ERROR: Could not get instance name from Terraform"
    exit 1
fi

echo "Instance: $INSTANCE_NAME"
echo "Zone: $ZONE"
echo "External IP: $EXTERNAL_IP"
echo ""

# Kill existing tunnels
echo "Cleaning up existing SSH tunnels..."
pkill -f "gcloud compute ssh.*$INSTANCE_NAME.*-L" 2>/dev/null || true
sleep 2

echo ""
echo "Creating SSH tunnels..."
echo ""
echo "  Local Port    Remote Service"
echo "  ----------    --------------"
echo "  9090       -> Dashboard (http://localhost:9090)"
echo "  8081       -> API (http://localhost:8081/api/v1/stats/overview)"
echo "  8080       -> CockroachDB Admin UI (http://localhost:8080)"
echo "  26257      -> Proxy (connect via localhost:26257)"
echo ""

# Create SSH tunnel in background
gcloud compute ssh "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --ssh-flag="-L 9090:localhost:9090" \
    --ssh-flag="-L 8081:localhost:8081" \
    --ssh-flag="-L 8080:localhost:8080" \
    --ssh-flag="-L 26257:localhost:26257" \
    --ssh-flag="-N" \
    --ssh-flag="-f" \
    2>/dev/null

echo "✓ SSH tunnels established"
echo ""

# Wait for tunnels to be ready
echo "Waiting for tunnels to initialize..."
sleep 3
echo ""

# Test connections
echo "Testing connections..."
echo ""

# Test Dashboard
if curl -s --max-time 5 http://localhost:9090 >/dev/null 2>&1; then
    echo "  ✓ Dashboard: http://localhost:9090"
else
    echo "  ⏳ Dashboard: Not ready yet"
fi

# Test API
if curl -s --max-time 5 http://localhost:8081/api/v1/stats/overview >/dev/null 2>&1; then
    echo "  ✓ API: http://localhost:8081/api/v1/stats/overview"
else
    echo "  ⏳ API: Not ready yet"
fi

# Test CockroachDB UI
if curl -s --max-time 5 http://localhost:8080 >/dev/null 2>&1; then
    echo "  ✓ CockroachDB UI: http://localhost:8080"
else
    echo "  ⏳ CockroachDB UI: Not ready yet"
fi

echo ""
echo "========================================="
echo "Dashboard Access Ready!"
echo "========================================="
echo ""
echo "Open in your browser:"
echo "  Dashboard:      http://localhost:9090"
echo "  API Stats:      http://localhost:8081/api/v1/stats/overview"
echo "  CRDB Admin:     http://localhost:8080"
echo ""
echo "Connect to proxy locally:"
echo "  psql -h localhost -p 26257 -U root defaultdb"
echo ""
echo "To close tunnels:"
echo "  pkill -f 'gcloud compute ssh.*$INSTANCE_NAME.*-L'"
echo ""
echo "Press Ctrl+C when done, or run in background"
echo ""

# Keep script running
echo "Tunnels active. Press Ctrl+C to close..."
tail -f /dev/null
