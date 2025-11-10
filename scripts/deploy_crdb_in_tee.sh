#!/bin/bash
set -e

# Deploy CockroachDB inside the same SEV-SNP VM as the proxy
# This script is designed to run on the GCP Confidential VM

CRDB_VERSION="${CRDB_VERSION:-v24.1.0}"
CRDB_DIR="/opt/cockroachdb"
CERTS_DIR="/opt/atls-proxy/certs"
PROXY_DIR="/opt/atls-proxy"

echo "======================================"
echo "Deploying CockroachDB in TEE"
echo "Version: ${CRDB_VERSION}"
echo "======================================"

# Check if running in SEV-SNP environment
check_sev_snp() {
    echo "Checking for SEV-SNP..."
    if dmesg | grep -qi "sev-snp"; then
        echo "✓ SEV-SNP detected"
    else
        echo "⚠ WARNING: SEV-SNP not detected. This may not be a confidential VM."
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Download and install CockroachDB
install_cockroach() {
    echo "Installing CockroachDB ${CRDB_VERSION}..."

    cd /tmp
    wget -q "https://binaries.cockroachdb.com/cockroach-${CRDB_VERSION}.linux-amd64.tgz"
    tar xzf "cockroach-${CRDB_VERSION}.linux-amd64.tgz"

    sudo cp "cockroach-${CRDB_VERSION}.linux-amd64/cockroach" /usr/local/bin/
    sudo chmod +x /usr/local/bin/cockroach

    # Verify installation
    cockroach version

    echo "✓ CockroachDB installed"
}

# Setup CockroachDB directories and certificates
setup_directories() {
    echo "Setting up directories..."

    sudo mkdir -p "${CRDB_DIR}/data"
    sudo mkdir -p "${CERTS_DIR}"
    sudo mkdir -p /var/log/cockroachdb

    echo "✓ Directories created"
}

# Generate certificates for CRDB
generate_certificates() {
    echo "Generating certificates..."

    cd "${CERTS_DIR}"

    # Generate CA certificate
    if [ ! -f ca.crt ]; then
        cockroach cert create-ca \
            --certs-dir="${CERTS_DIR}" \
            --ca-key="${CERTS_DIR}/ca.key"
        echo "✓ CA certificate generated"
    else
        echo "  CA certificate already exists"
    fi

    # Generate node certificate (for localhost)
    cockroach cert create-node \
        localhost \
        127.0.0.1 \
        ::1 \
        --certs-dir="${CERTS_DIR}" \
        --ca-key="${CERTS_DIR}/ca.key"
    echo "✓ Node certificate generated"

    # Generate client certificate for proxy
    cockroach cert create-client \
        proxy_user \
        --certs-dir="${CERTS_DIR}" \
        --ca-key="${CERTS_DIR}/ca.key"
    echo "✓ Proxy client certificate generated"

    # Generate client certificate for root user (admin)
    cockroach cert create-client \
        root \
        --certs-dir="${CERTS_DIR}" \
        --ca-key="${CERTS_DIR}/ca.key"
    echo "✓ Root client certificate generated"

    # Set proper permissions
    sudo chmod 600 "${CERTS_DIR}"/*.key
    sudo chmod 644 "${CERTS_DIR}"/*.crt
}

# Create systemd service for CockroachDB
create_systemd_service() {
    echo "Creating systemd service..."

    sudo tee /etc/systemd/system/cockroachdb.service > /dev/null <<EOF
[Unit]
Description=CockroachDB in TEE
After=network.target
Documentation=https://www.cockroachlabs.com/docs/

[Service]
Type=simple
User=root
WorkingDirectory=${CRDB_DIR}
ExecStart=/usr/local/bin/cockroach start-single-node \\
    --listen-addr=localhost:26258 \\
    --http-addr=localhost:8081 \\
    --store=${CRDB_DIR}/data \\
    --certs-dir=${CERTS_DIR} \\
    --log="{sinks: {stderr: {filter: INFO}, file-groups: {default: {dir: /var/log/cockroachdb}}}}"

ExecStop=/usr/local/bin/cockroach quit --host=localhost:26258 --certs-dir=${CERTS_DIR}

Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CRDB_DIR} /var/log/cockroachdb

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    echo "✓ Systemd service created"
}

# Start CockroachDB
start_cockroach() {
    echo "Starting CockroachDB..."

    sudo systemctl enable cockroachdb
    sudo systemctl start cockroachdb

    # Wait for CRDB to be ready
    echo "Waiting for CockroachDB to start..."
    for i in {1..30}; do
        if cockroach sql --host=localhost:26258 --certs-dir="${CERTS_DIR}" --execute="SELECT 1" > /dev/null 2>&1; then
            echo "✓ CockroachDB is ready"
            return 0
        fi
        echo -n "."
        sleep 2
    done

    echo "✗ CockroachDB failed to start"
    sudo journalctl -u cockroachdb -n 50
    exit 1
}

# Configure HBA to only allow localhost connections
configure_hba() {
    echo "Configuring Host-Based Authentication..."

    cockroach sql --host=localhost:26258 --certs-dir="${CERTS_DIR}" <<SQL
-- Only allow local connections (proxy is on same machine)
SET CLUSTER SETTING server.host_based_authentication.configuration = '
# TYPE  DATABASE  USER          ADDRESS         METHOD
local   all       all                           cert
hostssl all       all           127.0.0.1/32    cert
hostssl all       all           ::1/128         cert
hostssl all       all           0.0.0.0/0       reject
';
SQL

    echo "✓ HBA configured (localhost only)"
}

# Create proxy user with appropriate permissions
setup_proxy_user() {
    echo "Setting up proxy user..."

    cockroach sql --host=localhost:26258 --certs-dir="${CERTS_DIR}" <<SQL
CREATE USER IF NOT EXISTS proxy_user;
GRANT ADMIN TO proxy_user;

-- Create a test database
CREATE DATABASE IF NOT EXISTS testdb;
GRANT ALL ON DATABASE testdb TO proxy_user;

-- Show users
SELECT username, "isRole" FROM system.users;
SQL

    echo "✓ Proxy user created with ADMIN role"
}

# Display status and connection info
show_status() {
    echo ""
    echo "======================================"
    echo "CockroachDB Deployment Complete!"
    echo "======================================"
    echo ""
    echo "Status:"
    sudo systemctl status cockroachdb --no-pager -l
    echo ""
    echo "Connection Details:"
    echo "  Listen Address: localhost:26258"
    echo "  HTTP Console:   http://localhost:8081"
    echo "  Certificates:   ${CERTS_DIR}"
    echo "  Data Directory: ${CRDB_DIR}/data"
    echo ""
    echo "Test connection:"
    echo "  cockroach sql --host=localhost:26258 --certs-dir=${CERTS_DIR}"
    echo ""
    echo "View logs:"
    echo "  sudo journalctl -u cockroachdb -f"
    echo ""
}

# Main execution
main() {
    check_sev_snp
    install_cockroach
    setup_directories
    generate_certificates
    create_systemd_service
    start_cockroach
    configure_hba
    setup_proxy_user
    show_status
}

main "$@"