# GCP SEV-SNP Deployment for Attested TLS Proxy

This directory contains Terraform configuration to deploy the Attested TLS Proxy on a Google Cloud Platform Confidential VM with AMD SEV-SNP.

## What Gets Deployed

- **GCP Confidential VM** with AMD SEV-SNP (n2d-standard-4)
- **CockroachDB** (running on localhost:26258)
- **Attested TLS Proxy** (listening on 0.0.0.0:26257)
- **HTTP API** (port 8081)
- **Dashboard** (port 9090)
- **Firewall rules** for secure access
- **Service account** with minimal permissions

## Prerequisites

1. **GCP Account** with billing enabled
2. **gcloud CLI** installed and authenticated
3. **Terraform** >= 1.0 installed
4. **Project** with Compute Engine API enabled

### Setup

```bash
# Install gcloud CLI (if needed)
# https://cloud.google.com/sdk/docs/install

# Authenticate
gcloud auth login
gcloud auth application-default login

# Set project
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable compute.googleapis.com
gcloud services enable logging.googleapis.com
gcloud services enable monitoring.googleapis.com
```

## Deployment

### Option 1: Automated Deployment (Recommended)

```bash
cd terraform/gcp
chmod +x deploy.sh
./deploy.sh
```

This script will:
1. Check prerequisites
2. Initialize Terraform
3. Create deployment plan
4. Ask for confirmation
5. Deploy the VM
6. Run health checks
7. Display connection information

### Option 2: Manual Deployment

```bash
cd terraform/gcp

# Initialize
terraform init

# Plan
terraform plan -out=tfplan

# Apply
terraform apply tfplan

# Get outputs
terraform output
```

## Accessing the Dashboard

### Option A: Direct Access (Dashboard exposed to internet)

The deployment creates firewall rules allowing dashboard access from anywhere:

```bash
# Get dashboard URL
terraform output dashboard_url

# Open in browser
open $(terraform output -raw dashboard_url)
```

### Option B: SSH Tunnel (More Secure - Recommended)

For production, you should restrict firewall rules and use SSH tunnels:

```bash
chmod +x access-dashboard.sh
./access-dashboard.sh
```

This creates SSH tunnels for:
- Dashboard: http://localhost:9090
- API: http://localhost:8081
- CockroachDB UI: http://localhost:8080
- Proxy: localhost:26257

Then open http://localhost:9090 in your browser.

## Verifying SEV-SNP

### Check SEV-SNP is Enabled

```bash
# SSH to VM
terraform output -raw ssh_command | bash

# Check kernel logs
sudo dmesg | grep -i sev

# Check for /dev/sev-guest device
ls -l /dev/sev-guest

# Expected output:
# crw------- 1 root root 10, 125 Nov 13 12:34 /dev/sev-guest
```

### Test Real Hardware Attestation

```bash
# SSH to VM
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a

# Go to project directory
cd /opt/attested-tls-proxy-cockroach

# Run attestation test
export CGO_CFLAGS="-I/usr/include"
export CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lcrypto"
go run tests/integration/helpers/testclient/test_sev_attestation.go

# This should:
# 1. Call /dev/sev-guest ioctl
# 2. Get real 1184-byte attestation report
# 3. Display measurement hash, TCB version, etc.
```

## Monitoring

### View Logs

```bash
# SSH to VM
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a

# Proxy logs
tail -f /var/log/atls-proxy/proxy.log

# Dashboard logs
tail -f /var/log/atls-proxy/dashboard.log

# CockroachDB logs
tail -f /var/log/cockroach.log

# Deployment status
cat /var/log/deployment-status.txt
```

### Check Service Status

```bash
# SSH to VM
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a

# Check running processes
ps aux | grep -E 'cockroach|atls-proxy|dashboard'

# Check listening ports
sudo netstat -tlnp | grep -E '26257|26258|8081|9090'
```

### API Health Check

```bash
# From your local machine (if firewall allows)
EXTERNAL_IP=$(terraform output -raw external_ip)

# Statistics
curl http://$EXTERNAL_IP:8081/api/v1/stats/overview | jq

# Attestations
curl http://$EXTERNAL_IP:8081/api/v1/attestations | jq

# Active clients
curl http://$EXTERNAL_IP:8081/api/v1/clients/active | jq
```

## Testing Attested Connections

### From Local Machine

```bash
# Build test client locally
cd tests/integration/helpers/testclient
go build -o testclient main.go

# Connect to remote proxy
EXTERNAL_IP=$(cd ../../../terraform/gcp && terraform output -raw external_ip)
./testclient --proxy=$EXTERNAL_IP:26257
```

### From the VM

```bash
# SSH to VM
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a

# Run test clients
cd /opt/attested-tls-proxy-cockroach
go run tests/integration/helpers/testclient/connect_to_cluster.go

# Check dashboard
# You should see new attestation records appear
```

## Security Hardening

### Restrict Firewall Rules

Edit `main.tf` to restrict access to your IP:

```hcl
variable "allowed_ssh_cidrs" {
  default = ["YOUR_IP/32"]  # Your IP only
}

# For dashboard (comment out to disable public access)
resource "google_compute_firewall" "allow_dashboard" {
  # ...
  source_ranges = ["YOUR_IP/32"]  # Or remove this resource entirely
}
```

Then reapply:

```bash
terraform apply
```

### Use Identity-Aware Proxy (IAP)

For production, use GCP's Identity-Aware Proxy instead of public IPs:

```bash
# Enable IAP
gcloud compute instances add-iam-policy-binding \
    $(terraform output -raw instance_name) \
    --member='user:YOUR_EMAIL' \
    --role='roles/iap.tunnelResourceAccessor' \
    --zone=us-central1-a

# Connect via IAP tunnel
gcloud compute start-iap-tunnel \
    $(terraform output -raw instance_name) \
    9090 \
    --local-host-port=localhost:9090 \
    --zone=us-central1-a
```

## Cost Optimization

### Estimated Costs

- n2d-standard-4 (4 vCPUs, 16 GB): ~$150/month
- 50 GB SSD: ~$8.50/month
- Network egress: Variable

**Total: ~$160/month**

### Reduce Costs

```bash
# Use smaller instance (for testing)
terraform apply -var="machine_type=n2d-standard-2"

# Stop when not in use
gcloud compute instances stop $(terraform output -raw instance_name) --zone=us-central1-a

# Start when needed
gcloud compute instances start $(terraform output -raw instance_name) --zone=us-central1-a
```

## Cleanup

### Destroy All Resources

```bash
terraform destroy
```

This removes:
- VM instance
- Firewall rules
- VPC network
- Service account

## Troubleshooting

### Services Not Starting

```bash
# Check startup script logs
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a \
    --command="sudo journalctl -u google-startup-scripts.service"

# Check deployment status
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a \
    --command="cat /var/log/deployment-status.txt"
```

### SEV-SNP Not Available

```bash
# Check if SEV-SNP is supported in your zone
gcloud compute machine-types list \
    --filter="name:n2d-standard AND zone:us-central1-a" \
    --format="table(name,zone,description)"

# Try different zone
terraform apply -var="zone=us-central1-b"
```

### Dashboard Not Accessible

```bash
# Check firewall rules
gcloud compute firewall-rules list --filter="name~attested-proxy"

# Check if dashboard is running
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a \
    --command="curl -s http://localhost:9090 | head -20"

# Check logs
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a \
    --command="tail -50 /var/log/atls-proxy/dashboard.log"
```

### Attestation Failing

```bash
# Check if /dev/sev-guest exists
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a \
    --command="ls -l /dev/sev-guest"

# Check proxy logs for attestation errors
gcloud compute ssh $(terraform output -raw instance_name) --zone=us-central1-a \
    --command="grep -i 'attestation\|sev' /var/log/atls-proxy/proxy.log | tail -20"
```

## Next Steps

1. **Access Dashboard**: `./access-dashboard.sh` then open http://localhost:9090
2. **Test Attestation**: Run test clients and verify they appear in dashboard
3. **Review Logs**: Check `/var/log/atls-proxy/` for attestation verification
4. **Harden Security**: Restrict firewall rules to your IP
5. **Monitor Costs**: Use GCP billing alerts

## Support

- [Attested TLS Proxy Documentation](../../README.md)
- [GCP Confidential Computing](https://cloud.google.com/confidential-computing)
- [AMD SEV-SNP Documentation](https://www.amd.com/en/developer/sev.html)
