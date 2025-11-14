# GCP Confidential VM with AMD SEV-SNP for Attested TLS Proxy
# This creates a production-ready SEV-SNP VM with CockroachDB and the attested proxy

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Variables
variable "project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "cockroach-workers"
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP Zone (must support AMD SEV-SNP)"
  type        = string
  default     = "us-central1-a"
}

variable "instance_name" {
  description = "Name of the VM instance"
  type        = string
  default     = "attested-tls-proxy-sev"
}

variable "machine_type" {
  description = "Machine type (must be n2d for AMD SEV-SNP)"
  type        = string
  default     = "n2d-standard-4"  # 4 vCPUs, 16 GB RAM
}

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 50
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # CHANGE IN PRODUCTION
}

# VPC Network
resource "google_compute_network" "vpc" {
  name                    = "${var.instance_name}-vpc"
  auto_create_subnetworks = false
}

# Subnet
resource "google_compute_subnetwork" "subnet" {
  name          = "${var.instance_name}-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id
}

# Firewall - Allow SSH
resource "google_compute_firewall" "allow_ssh" {
  name    = "${var.instance_name}-allow-ssh"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.allowed_ssh_cidrs
  target_tags   = ["attested-proxy"]
}

# Firewall - Allow Proxy (CockroachDB wire protocol)
resource "google_compute_firewall" "allow_proxy" {
  name    = "${var.instance_name}-allow-proxy"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["26257"]  # Proxy listen port
  }

  source_ranges = ["0.0.0.0/0"]  # Clients connecting to proxy
  target_tags   = ["attested-proxy"]
}

# Firewall - Allow Dashboard
resource "google_compute_firewall" "allow_dashboard" {
  name    = "${var.instance_name}-allow-dashboard"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["9090"]  # Dashboard port
  }

  source_ranges = ["0.0.0.0/0"]  # Or restrict to your IP
  target_tags   = ["attested-proxy"]
}

# Firewall - Allow API
resource "google_compute_firewall" "allow_api" {
  name    = "${var.instance_name}-allow-api"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8081"]  # Proxy HTTP API
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["attested-proxy"]
}

# Startup script
locals {
  startup_script = <<-EOT
#!/bin/bash
set -e

# Install dependencies
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y wget curl git build-essential libssl-dev pkg-config sqlite3

# Install Go 1.21
cd /tmp
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/root/go
mkdir -p $GOPATH

# Install CockroachDB
wget -qO- https://binaries.cockroachdb.com/cockroach-v23.2.0.linux-amd64.tgz | tar xvz
cp -i cockroach-v23.2.0.linux-amd64/cockroach /usr/local/bin/
chmod +x /usr/local/bin/cockroach

# Clone proxy repository
cd /opt
git clone https://github.com/souravcrl/attested-tls-proxy-cockroach.git
cd attested-tls-proxy-cockroach

# Build proxy
export CGO_CFLAGS="-I/usr/include"
export CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lcrypto"
make build

# Create directories
mkdir -p /var/lib/cockroach /var/lib/atls-proxy /var/log/atls-proxy

# Start CockroachDB (localhost only for security)
nohup cockroach start-single-node \
  --insecure \
  --listen-addr=localhost:26258 \
  --http-addr=localhost:8080 \
  --store=/var/lib/cockroach \
  > /var/log/cockroach.log 2>&1 &

# Wait for CockroachDB to start
sleep 10

# Update proxy config for SEV-SNP
cat > /opt/attested-tls-proxy-cockroach/config/production-sev.yaml <<EOF
proxy:
  node_id: "proxy-sev-1"
  listen: "0.0.0.0:26257"
  backend:
    host: "localhost"
    port: 26258
    tls:
      enabled: false
  api:
    enabled: true
    listen: "0.0.0.0:8081"

attestation:
  provider: "sev-snp"  # REAL HARDWARE
  policy_file: "config/attestation-policy.yaml"
  nonce_ttl: 300s
  storage:
    db_path: "/var/lib/atls-proxy/attestations.db"
    retention_days: 30

logging:
  level: "info"
  audit_file: "/var/log/atls-proxy/audit.json"
EOF

# Start proxy
cd /opt/attested-tls-proxy-cockroach
export CGO_CFLAGS="-I/usr/include"
export CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lcrypto"
nohup ./bin/atls-proxy --config config/production-sev.yaml \
  > /var/log/atls-proxy/proxy.log 2>&1 &

# Start dashboard
nohup ./cmd/dashboard/dashboard \
  --listen=0.0.0.0:9090 \
  --proxies=localhost:8081 \
  > /var/log/atls-proxy/dashboard.log 2>&1 &

echo "Deployment complete!" > /var/log/deployment-status.txt
EOT
}

# Confidential VM Instance with AMD SEV-SNP
resource "google_compute_instance" "sev_vm" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["attested-proxy"]

  # SEV-SNP Configuration
  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "SEV_SNP"  # AMD SEV-SNP
  }

  # Advanced Machine Features
  advanced_machine_features {
    enable_nested_virtualization = false
    threads_per_core            = 2  # SMT can be enabled for performance
  }

  # Scheduling (SEV-SNP VMs cannot be live migrated)
  scheduling {
    on_host_maintenance = "TERMINATE"
    automatic_restart   = true
  }

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet.id

    # External IP for SSH and client access
    access_config {
      # Ephemeral public IP
    }
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  metadata_startup_script = local.startup_script

  # Use default compute service account
  service_account {
    scopes = ["cloud-platform"]
  }

  # Labels
  labels = {
    environment = "production"
    component   = "attested-tls-proxy"
    tee         = "sev-snp"
  }
}

# Outputs
output "instance_name" {
  description = "Name of the created instance"
  value       = google_compute_instance.sev_vm.name
}

output "instance_id" {
  description = "ID of the created instance"
  value       = google_compute_instance.sev_vm.id
}

output "external_ip" {
  description = "External IP address"
  value       = google_compute_instance.sev_vm.network_interface[0].access_config[0].nat_ip
}

output "internal_ip" {
  description = "Internal IP address"
  value       = google_compute_instance.sev_vm.network_interface[0].network_ip
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "gcloud compute ssh ${google_compute_instance.sev_vm.name} --zone=${var.zone}"
}

output "proxy_endpoint" {
  description = "Proxy endpoint for clients"
  value       = "${google_compute_instance.sev_vm.network_interface[0].access_config[0].nat_ip}:26257"
}

output "dashboard_url" {
  description = "Dashboard URL"
  value       = "http://${google_compute_instance.sev_vm.network_interface[0].access_config[0].nat_ip}:9090"
}

output "api_url" {
  description = "API endpoint"
  value       = "http://${google_compute_instance.sev_vm.network_interface[0].access_config[0].nat_ip}:8081"
}

output "verify_sev_command" {
  description = "Command to verify SEV-SNP is enabled"
  value       = "gcloud compute ssh ${google_compute_instance.sev_vm.name} --zone=${var.zone} --command='sudo dmesg | grep -i sev'"
}
