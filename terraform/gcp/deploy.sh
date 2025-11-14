#!/bin/bash
# Deploy Attested TLS Proxy to GCP with AMD SEV-SNP
set -e

echo "========================================="
echo "Attested TLS Proxy - GCP SEV-SNP Deployment"
echo "========================================="
echo ""

# Check prerequisites
command -v terraform >/dev/null 2>&1 || { echo "ERROR: terraform not installed"; exit 1; }
command -v gcloud >/dev/null 2>&1 || { echo "ERROR: gcloud not installed"; exit 1; }

# Check GCP authentication
echo "Checking GCP authentication..."
GCLOUD_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
if [ -z "$GCLOUD_ACCOUNT" ]; then
    echo "ERROR: Not authenticated to GCP"
    echo "Run: gcloud auth login"
    exit 1
fi
echo "✓ Authenticated as: $GCLOUD_ACCOUNT"

# Get project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: No GCP project set"
    echo "Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi
echo "✓ Project: $PROJECT_ID"
echo ""

# Initialize Terraform
echo "Initializing Terraform..."
terraform init
echo ""

# Plan deployment
echo "Planning deployment..."
terraform plan \
    -var="project_id=$PROJECT_ID" \
    -out=tfplan
echo ""

# Confirm deployment
read -p "Deploy to GCP? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Deployment cancelled"
    exit 0
fi
echo ""

# Apply
echo "Deploying SEV-SNP VM..."
terraform apply tfplan
echo ""

# Get outputs
echo "========================================="
echo "Deployment Complete!"
echo "========================================="
terraform output -json > deployment-info.json

EXTERNAL_IP=$(terraform output -raw external_ip)
DASHBOARD_URL=$(terraform output -raw dashboard_url)
API_URL=$(terraform output -raw api_url)
SSH_COMMAND=$(terraform output -raw ssh_command)

echo ""
echo "VM Information:"
echo "  External IP: $EXTERNAL_IP"
echo "  SSH: $SSH_COMMAND"
echo ""
echo "Service Endpoints:"
echo "  Proxy: $EXTERNAL_IP:26257"
echo "  Dashboard: $DASHBOARD_URL"
echo "  API: $API_URL/api/v1/stats/overview"
echo ""
echo "Waiting for services to start (60 seconds)..."
sleep 60
echo ""

# Health check
echo "Running health checks..."
echo ""

# Check SSH
echo "1. Testing SSH access..."
if gcloud compute ssh $(terraform output -raw instance_name) \
    --zone=us-central1-a \
    --command="echo 'SSH OK'" 2>/dev/null; then
    echo "   ✓ SSH access working"
else
    echo "   ✗ SSH access failed"
fi

# Check SEV-SNP
echo ""
echo "2. Verifying AMD SEV-SNP..."
gcloud compute ssh $(terraform output -raw instance_name) \
    --zone=us-central1-a \
    --command="sudo dmesg | grep -i sev | head -5" 2>/dev/null || echo "   Check manually"

# Check /dev/sev-guest
echo ""
echo "3. Checking /dev/sev-guest device..."
gcloud compute ssh $(terraform output -raw instance_name) \
    --zone=us-central1-a \
    --command="ls -l /dev/sev-guest 2>/dev/null || echo 'Device not found - may not be available yet'" 2>/dev/null

# Check services
echo ""
echo "4. Checking service status..."
gcloud compute ssh $(terraform output -raw instance_name) \
    --zone=us-central1-a \
    --command="pgrep -a 'cockroach|atls-proxy|dashboard' || echo 'Services still starting...'" 2>/dev/null

# Check API
echo ""
echo "5. Testing API endpoint..."
sleep 30  # Give services more time
if curl -s --max-time 5 "$API_URL/api/v1/stats/overview" >/dev/null 2>&1; then
    echo "   ✓ API responding"
    curl -s "$API_URL/api/v1/stats/overview" | python3 -m json.tool 2>/dev/null || true
else
    echo "   ⏳ API not ready yet (this is normal, services are still starting)"
fi

echo ""
echo "========================================="
echo "Next Steps:"
echo "========================================="
echo ""
echo "1. Access Dashboard:"
echo "   Open: $DASHBOARD_URL"
echo ""
echo "2. SSH to VM:"
echo "   $SSH_COMMAND"
echo ""
echo "3. View logs:"
echo "   tail -f /var/log/atls-proxy/proxy.log"
echo "   tail -f /var/log/atls-proxy/dashboard.log"
echo "   tail -f /var/log/cockroach.log"
echo ""
echo "4. Test attestation:"
echo "   cd /opt/attested-tls-proxy-cockroach"
echo "   go run tests/integration/helpers/testclient/connect_to_cluster.go"
echo ""
echo "5. Destroy when done:"
echo "   terraform destroy"
echo ""

# Save connection info
cat > ../DEPLOYMENT.txt <<EOF
GCP SEV-SNP Deployment Information
Generated: $(date)

External IP: $EXTERNAL_IP
Dashboard: $DASHBOARD_URL
API: $API_URL
SSH: $SSH_COMMAND

Proxy Endpoint: $EXTERNAL_IP:26257
CockroachDB: localhost:26258 (internal only)

Services:
- Attested TLS Proxy: port 26257
- HTTP API: port 8081
- Dashboard: port 9090
- CockroachDB: localhost:26258

Logs:
- Proxy: /var/log/atls-proxy/proxy.log
- Dashboard: /var/log/atls-proxy/dashboard.log
- CockroachDB: /var/log/cockroach.log
- Deployment: /var/log/deployment-status.txt

Configuration:
- Proxy config: /opt/attested-tls-proxy-cockroach/config/production-sev.yaml
- Attestation storage: /var/lib/atls-proxy/attestations.db
- CRDB data: /var/lib/cockroach
EOF

echo "Deployment info saved to: ../DEPLOYMENT.txt"
echo ""
