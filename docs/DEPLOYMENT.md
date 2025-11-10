# Deployment Guide

This guide covers deploying the Attested TLS Proxy with CockroachDB in a GCP SEV-SNP Confidential VM.

## Architecture Overview

```
┌────────────────── SEV-SNP VM (GCP) ────────────────┐
│                                                     │
│  ┌────────┐ localhost ┌──────────────┐            │
│  │ Proxy  │─────────>│ CockroachDB  │            │
│  │ :26257 │    TLS   │  :26258      │            │
│  └────────┘          └──────────────┘            │
│       ▲                                            │
│       │ aTLS (Attested TLS)                       │
└───────┼────────────────────────────────────────────┘
        │
   ┌────────┐
   │ Client │
   └────────┘
```

**Key Points:**
- Both proxy and CockroachDB run in the SAME SEV-SNP VM
- CockroachDB listens on localhost:26258 only (no external access)
- Proxy listens on 0.0.0.0:26257 (external clients)
- Connection between proxy and CRDB is over TLS on localhost
- Full attestation covers both binaries

## Prerequisites

1. **GCP Account** with Confidential Computing enabled
2. **Terraform** >= 1.0 installed
3. **gcloud CLI** configured with your project
4. **SSH access** to GCP VMs

## Deployment Steps

### 1. Configure Terraform Variables

Create `iac/terraform/terraform.tfvars`:

```hcl
project_id           = "your-gcp-project-id"
region               = "us-central1"
deployment_name      = "atls-proxy"
environment          = "prod"
machine_type         = "n2d-standard-8"  # Must be n2d (AMD Milan)
boot_disk_size_gb    = 100  # Space for CRDB data

# Security: Restrict these in production!
allowed_client_cidrs = ["0.0.0.0/0"]  # Replace with your client IPs
allowed_ssh_cidrs    = ["0.0.0.0/0"]  # Replace with your admin IPs
```

### 2. Deploy Infrastructure

```bash
cd iac/terraform

# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Deploy
terraform apply

# Save outputs
terraform output > outputs.txt
```

**Outputs:**
- `proxy_external_ip`: Public IP for client connections
- `ssh_command`: Command to SSH into the VM
- `connection_string`: PostgreSQL connection string template

### 3. Verify Deployment

SSH into the VM:

```bash
# Use the ssh_command from terraform output
gcloud compute ssh atls-proxy-vm --zone=us-central1-a --project=your-project-id
```

Check services:

```bash
# Check CockroachDB status
sudo systemctl status cockroachdb

# Check proxy status
sudo systemctl status atls-proxy

# View logs
sudo journalctl -u cockroachdb -f
sudo journalctl -u atls-proxy -f
```

### 4. Verify SEV-SNP

```bash
# Check for SEV-SNP in kernel messages
dmesg | grep -i sev-snp

# Should see something like:
# SEV-SNP: enabled
# Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP
```

### 5. Test Connection

From your local machine:

```bash
# Get the external IP from terraform output
PROXY_IP=$(terraform output -raw proxy_external_ip)

# Test connection (will fail without proper auth, but verifies proxy is listening)
psql "postgresql://root@${PROXY_IP}:26257/defaultdb?sslmode=require"
```

## Configuration

### Proxy Configuration

The proxy configuration is deployed at `/opt/atls-proxy/config/proxy.yaml`:

```yaml
proxy:
  listen: "0.0.0.0:26257"
  backend:
    host: "localhost"
    port: 26258
    tls:
      enabled: true
      ca_cert: "/opt/atls-proxy/certs/ca.crt"
      client_cert: "/opt/atls-proxy/certs/client.proxy_user.crt"
      client_key: "/opt/atls-proxy/certs/client.proxy_user.key"

attestation:
  provider: "sev-snp"
  policy_file: "/opt/atls-proxy/policy.yaml"
  nonce_ttl: 300s

logging:
  level: "info"
  audit_file: "/var/log/atls-proxy/audit.json"
```

### CockroachDB Configuration

CockroachDB is configured via systemd to:
- Listen on `localhost:26258` only
- Use TLS with certificates in `/opt/atls-proxy/certs`
- Store data in `/opt/cockroachdb/data`
- Allow only local connections (via HBA)

## Security Hardening

### 1. Restrict Network Access

Edit `iac/terraform/terraform.tfvars`:

```hcl
# Only allow specific client IPs
allowed_client_cidrs = [
  "203.0.113.0/24",  # Your office network
  "198.51.100.50/32" # Specific client
]

# Only allow SSH from admin IPs
allowed_ssh_cidrs = [
  "203.0.113.10/32"  # Admin workstation
]
```

Then redeploy:

```bash
terraform apply
```

### 2. Update Firewall Rules

Additional firewall rules in GCP Console:
- Deny all outbound traffic except to trusted services
- Enable VPC Flow Logs for monitoring
- Setup Cloud Armor for DDoS protection

### 3. Enable Audit Logging

Proxy audit logs are written to:
```
/var/log/atls-proxy/audit.json
```

Configure log shipping to Cloud Logging:

```bash
# Install logging agent
curl -sSO https://dl.google.com/cloudagents/add-logging-agent-repo.sh
sudo bash add-logging-agent-repo.sh
sudo apt-get update
sudo apt-get install -y google-fluentd

# Configure to ship proxy logs
sudo tee /etc/google-fluentd/config.d/proxy-audit.conf <<EOF
<source>
  @type tail
  path /var/log/atls-proxy/audit.json
  pos_file /var/lib/google-fluentd/pos/proxy-audit.pos
  tag proxy.audit
  <parse>
    @type json
  </parse>
</source>
EOF

sudo systemctl restart google-fluentd
```

## Binary Measurements

### Generate Measurements

After deployment, generate measurements for attestation:

```bash
# SSH into the VM
gcloud compute ssh atls-proxy-vm --zone=us-central1-a

# Generate measurements
sudo /opt/atls-proxy/scripts/generate_measurements.sh

# View the policy file
cat /opt/atls-proxy/policy.yaml
```

Example output:
```yaml
measurements:
  - name: "proxy"
    sha384: "a1b2c3d4e5f6..."
    description: "Attested TLS Proxy binary"
    path: "/opt/atls-proxy/bin/atls-proxy"

  - name: "cockroachdb"
    sha384: "f6e5d4c3b2a1..."
    description: "CockroachDB binary"
    path: "/usr/local/bin/cockroach"

tcb_version_min: "1.51"
nonce_ttl: 300s
```

### Update Policy After Software Upgrades

Whenever you update the proxy or CockroachDB binaries:

1. Regenerate measurements:
   ```bash
   sudo /opt/atls-proxy/scripts/generate_measurements.sh
   ```

2. Restart proxy:
   ```bash
   sudo systemctl restart atls-proxy
   ```

3. Update client-side policy verification with new hashes

## Monitoring

### Metrics

The proxy exposes Prometheus metrics (future implementation):
- `atls_attestation_verifications_total`
- `atls_attestation_failures_total`
- `atls_backend_requests_total`
- `atls_connection_duration_seconds`

### Health Checks

Check proxy health:
```bash
curl http://localhost:8080/health
```

### Logs

View logs:
```bash
# Proxy logs
sudo journalctl -u atls-proxy -f

# CockroachDB logs
sudo journalctl -u cockroachdb -f

# Startup script logs
sudo cat /var/log/startup-script.log
```

## Maintenance

### Restart Services

```bash
# Restart CockroachDB
sudo systemctl restart cockroachdb

# Restart proxy
sudo systemctl restart atls-proxy

# Restart both
sudo systemctl restart cockroachdb atls-proxy
```

### Update Proxy Binary

```bash
# Build new binary locally
make build

# Copy to VM
gcloud compute scp bin/atls-proxy atls-proxy-vm:/tmp/atls-proxy --zone=us-central1-a

# SSH into VM
gcloud compute ssh atls-proxy-vm --zone=us-central1-a

# Stop proxy
sudo systemctl stop atls-proxy

# Replace binary
sudo cp /tmp/atls-proxy /opt/atls-proxy/bin/atls-proxy
sudo chmod +x /opt/atls-proxy/bin/atls-proxy

# Regenerate measurements
sudo /opt/atls-proxy/scripts/generate_measurements.sh

# Start proxy
sudo systemctl start atls-proxy
```

### Update CockroachDB

```bash
# SSH into VM
gcloud compute ssh atls-proxy-vm --zone=us-central1-a

# Download new version
CRDB_VERSION="v24.2.0"  # Update version
cd /tmp
wget "https://binaries.cockroachdb.com/cockroach-${CRDB_VERSION}.linux-amd64.tgz"
tar xzf "cockroach-${CRDB_VERSION}.linux-amd64.tgz"

# Stop services
sudo systemctl stop atls-proxy cockroachdb

# Replace binary
sudo cp "cockroach-${CRDB_VERSION}.linux-amd64/cockroach" /usr/local/bin/cockroach
sudo chmod +x /usr/local/bin/cockroach

# Regenerate measurements
sudo /opt/atls-proxy/scripts/generate_measurements.sh

# Start services
sudo systemctl start cockroachdb atls-proxy
```

## Disaster Recovery

### Backup CockroachDB Data

```bash
# Create backup
cockroach sql --host=localhost:26258 --certs-dir=/opt/atls-proxy/certs <<SQL
BACKUP DATABASE defaultdb TO 'gs://your-bucket/backups/latest';
SQL
```

### Restore from Backup

```bash
cockroach sql --host=localhost:26258 --certs-dir=/opt/atls-proxy/certs <<SQL
RESTORE DATABASE defaultdb FROM 'gs://your-bucket/backups/latest';
SQL
```

### Complete VM Restore

1. Destroy existing VM:
   ```bash
   terraform destroy
   ```

2. Restore from backup, then redeploy:
   ```bash
   terraform apply
   ```

## Troubleshooting

### Proxy Won't Start

Check logs:
```bash
sudo journalctl -u atls-proxy -n 100
```

Common issues:
- **"failed to connect to backend"**: CockroachDB not running
  ```bash
  sudo systemctl status cockroachdb
  ```

- **"failed to load TLS config"**: Certificate files missing
  ```bash
  ls -la /opt/atls-proxy/certs/
  ```

- **"address already in use"**: Port 26257 already bound
  ```bash
  sudo lsof -i :26257
  ```

### CockroachDB Won't Start

Check logs:
```bash
sudo journalctl -u cockroachdb -n 100
```

Common issues:
- **"certificate errors"**: Regenerate certificates
  ```bash
  cd /opt/atls-proxy/certs
  cockroach cert create-node localhost 127.0.0.1 --certs-dir=. --ca-key=ca.key
  ```

- **"data directory not empty"**: Clean slate needed
  ```bash
  sudo systemctl stop cockroachdb
  sudo rm -rf /opt/cockroachdb/data/*
  sudo systemctl start cockroachdb
  ```

### SEV-SNP Not Detected

Verify VM configuration:
```bash
# Check machine type
gcloud compute instances describe atls-proxy-vm --zone=us-central1-a --format="value(machineType)"

# Should be: n2d-standard-*

# Check confidential computing
gcloud compute instances describe atls-proxy-vm --zone=us-central1-a --format="value(confidentialInstanceConfig)"
```

If not enabled, VM must be recreated with correct configuration.

### Connection Refused from Client

1. Check firewall:
   ```bash
   gcloud compute firewall-rules list --filter="name~atls-proxy"
   ```

2. Verify proxy is listening:
   ```bash
   sudo netstat -tlnp | grep 26257
   ```

3. Test from VM itself:
   ```bash
   # From inside the VM
   psql "postgresql://root@localhost:26257/defaultdb?sslmode=require"
   ```

## Next Steps

1. **Implement Attestation**: See [PLAN.md](../PLAN.md) Phase 2-3 for adding SEV-SNP attestation
2. **Setup Monitoring**: Configure Prometheus and Grafana dashboards
3. **Enable Authentication**: Implement OAuth Token Exchange (STS)
4. **Production Hardening**: Follow security checklist in [SECURITY.md](./SECURITY.md)

## Support

- Issues: https://github.com/souravcrl/attested-tls-proxy-cockroach/issues
- Documentation: https://github.com/souravcrl/attested-tls-proxy-cockroach/docs