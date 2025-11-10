#!/bin/bash
set -e

# Startup script for GCP SEV-SNP VM
# This script runs on first boot to set up both CockroachDB and the proxy

PROJECT_ID="${project_id}"
REGION="${region}"
PROXY_DIR="/opt/atls-proxy"
LOG_FILE="/var/log/startup-script.log"

exec > >(tee -a "$LOG_FILE")
exec 2>&1

echo "======================================"
echo "Attested TLS Proxy Startup Script"
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Timestamp: $(date)"
echo "======================================"

# Update system
echo "Updating system packages..."
apt-get update
apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    jq \
    ca-certificates

# Verify SEV-SNP
echo "Checking for SEV-SNP support..."
if dmesg | grep -qi "sev-snp"; then
    echo "✓ SEV-SNP detected"
    dmesg | grep -i sev
else
    echo "⚠ WARNING: SEV-SNP not detected!"
fi

# Install Go (for building proxy from source if needed)
echo "Installing Go..."
GO_VERSION="1.22.0"
wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
rm -rf /usr/local/go
tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile

# Create directory structure
echo "Creating directories..."
mkdir -p "$PROXY_DIR"/{bin,certs,logs,config}
mkdir -p /var/log/atls-proxy

# Download and install proxy binary
echo "Installing proxy..."
cd "$PROXY_DIR"

# Option 1: Download pre-built binary from GCS (recommended for production)
# gsutil cp "gs://$PROJECT_ID-artifacts/atls-proxy" "$PROXY_DIR/bin/atls-proxy"

# Option 2: Build from source (for development)
git clone https://github.com/souravcrl/attested-tls-proxy-cockroach.git /tmp/proxy-src
cd /tmp/proxy-src
/usr/local/go/bin/go build -o "$PROXY_DIR/bin/atls-proxy" ./cmd/proxy
chmod +x "$PROXY_DIR/bin/atls-proxy"

# Decode and write proxy configuration
echo "Writing proxy configuration..."
echo "${proxy_config}" | base64 -d > "$PROXY_DIR/config/proxy.yaml"

# Deploy CockroachDB in the same TEE
echo "Deploying CockroachDB..."
if [ -f /tmp/proxy-src/scripts/deploy_crdb_in_tee.sh ]; then
    chmod +x /tmp/proxy-src/scripts/deploy_crdb_in_tee.sh
    /tmp/proxy-src/scripts/deploy_crdb_in_tee.sh
else
    echo "ERROR: CRDB deployment script not found!"
    exit 1
fi

# Wait for CockroachDB to be ready
echo "Waiting for CockroachDB..."
for i in {1..30}; do
    if cockroach sql --host=localhost:26258 --certs-dir="$PROXY_DIR/certs" --execute="SELECT 1" > /dev/null 2>&1; then
        echo "✓ CockroachDB is ready"
        break
    fi
    sleep 2
done

# Create systemd service for proxy
echo "Creating proxy systemd service..."
cat > /etc/systemd/system/atls-proxy.service <<EOF
[Unit]
Description=Attested TLS Proxy
After=network.target cockroachdb.service
Wants=cockroachdb.service
Documentation=https://github.com/souravcrl/attested-tls-proxy-cockroach

[Service]
Type=simple
User=root
WorkingDirectory=$PROXY_DIR
ExecStart=$PROXY_DIR/bin/atls-proxy --config $PROXY_DIR/config/proxy.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Environment
Environment="PATH=/usr/local/go/bin:/usr/bin:/bin"

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start proxy service
echo "Starting proxy service..."
systemctl daemon-reload
systemctl enable atls-proxy
systemctl start atls-proxy

# Wait for proxy to start
sleep 5

# Check status
echo ""
echo "======================================"
echo "Deployment Status"
echo "======================================"
echo ""
echo "CockroachDB:"
systemctl status cockroachdb --no-pager || true
echo ""
echo "Proxy:"
systemctl status atls-proxy --no-pager || true
echo ""

# Display connection information
EXTERNAL_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)

echo "======================================"
echo "Deployment Complete!"
echo "======================================"
echo ""
echo "External IP: $EXTERNAL_IP"
echo "Proxy Port:  26257"
echo ""
echo "Connection string:"
echo "  postgresql://[user]@$EXTERNAL_IP:26257/defaultdb?sslmode=require"
echo ""
echo "View logs:"
echo "  sudo journalctl -u atls-proxy -f"
echo "  sudo journalctl -u cockroachdb -f"
echo ""
echo "Access CockroachDB CLI (local only):"
echo "  cockroach sql --host=localhost:26258 --certs-dir=$PROXY_DIR/certs"
echo ""

# Generate measurements for attestation policy
echo "Generating binary measurements..."
if [ -f /tmp/proxy-src/scripts/generate_measurements.sh ]; then
    chmod +x /tmp/proxy-src/scripts/generate_measurements.sh
    /tmp/proxy-src/scripts/generate_measurements.sh
fi

echo "Startup script completed successfully!"
