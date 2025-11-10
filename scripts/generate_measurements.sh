#!/bin/bash
set -e

# Generate binary measurements for attestation policy
# This script computes SHA-384 hashes of the proxy and CockroachDB binaries

PROXY_BIN="${PROXY_BIN:-/opt/atls-proxy/bin/atls-proxy}"
CRDB_BIN="${CRDB_BIN:-/usr/local/bin/cockroach}"
OUTPUT_FILE="${OUTPUT_FILE:-/opt/atls-proxy/policy.yaml}"

echo "======================================"
echo "Generating Binary Measurements"
echo "======================================"

# Check if binaries exist
check_binary() {
    local bin_path=$1
    local bin_name=$2

    if [ ! -f "$bin_path" ]; then
        echo "ERROR: $bin_name binary not found at $bin_path"
        return 1
    fi

    if [ ! -x "$bin_path" ]; then
        echo "ERROR: $bin_name binary is not executable"
        return 1
    fi

    echo "✓ Found $bin_name at $bin_path"
    return 0
}

echo "Checking binaries..."
check_binary "$PROXY_BIN" "Proxy" || exit 1
check_binary "$CRDB_BIN" "CockroachDB" || exit 1

# Compute SHA-384 hashes
echo ""
echo "Computing SHA-384 hashes..."

PROXY_HASH=$(sha384sum "$PROXY_BIN" | awk '{print $1}')
echo "Proxy:       $PROXY_HASH"

CRDB_HASH=$(sha384sum "$CRDB_BIN" | awk '{print $1}')
echo "CockroachDB: $CRDB_HASH"

# Get kernel version (for reference)
KERNEL_VERSION=$(uname -r)
echo "Kernel:      $KERNEL_VERSION"

# Create policy file
echo ""
echo "Creating policy file: $OUTPUT_FILE"

cat > "$OUTPUT_FILE" <<EOF
# Attestation Policy
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Host: $(hostname)

measurements:
  - name: "proxy"
    sha384: "$PROXY_HASH"
    description: "Attested TLS Proxy binary"
    path: "$PROXY_BIN"

  - name: "cockroachdb"
    sha384: "$CRDB_HASH"
    description: "CockroachDB binary"
    path: "$CRDB_BIN"

# Minimum Trusted Computing Base (TCB) version for AMD SEV-SNP
tcb_version_min: "1.51"

# Nonce time-to-live (prevent replay attacks)
nonce_ttl: 300s  # 5 minutes

# Additional policy settings
allow_simulated: false  # MUST be false in production

metadata:
  generated_at: "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  kernel_version: "$KERNEL_VERSION"
  hostname: "$(hostname)"
EOF

chmod 600 "$OUTPUT_FILE"

echo "✓ Policy file created"

# Display the policy
echo ""
echo "======================================"
echo "Policy File Contents"
echo "======================================"
cat "$OUTPUT_FILE"

echo ""
echo "======================================"
echo "Measurement Summary"
echo "======================================"
echo ""
echo "The following binaries have been measured:"
echo ""
echo "  1. Proxy:       $(basename $PROXY_BIN)"
echo "     Hash:        $PROXY_HASH"
echo "     Size:        $(stat -c%s "$PROXY_BIN" 2>/dev/null || stat -f%z "$PROXY_BIN") bytes"
echo ""
echo "  2. CockroachDB: $(basename $CRDB_BIN)"
echo "     Hash:        $CRDB_HASH"
echo "     Size:        $(stat -c%s "$CRDB_BIN" 2>/dev/null || stat -f%z "$CRDB_BIN") bytes"
echo ""
echo "IMPORTANT:"
echo "  - These measurements MUST match during attestation verification"
echo "  - ANY change to the binaries will change the hash"
echo "  - Update this policy file whenever you update the software"
echo "  - Store this policy file securely"
echo ""

# Create a backup
BACKUP_FILE="${OUTPUT_FILE}.$(date +%Y%m%d_%H%M%S).bak"
cp "$OUTPUT_FILE" "$BACKUP_FILE"
echo "Backup created: $BACKUP_FILE"

echo ""
echo "Measurement generation complete!"
