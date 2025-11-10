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
}

# VPC Network for the proxy
resource "google_compute_network" "atls_network" {
  name                    = "${var.deployment_name}-network"
  auto_create_subnetworks = false
  description             = "Network for Attested TLS Proxy"
}

resource "google_compute_subnetwork" "atls_subnet" {
  name          = "${var.deployment_name}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.atls_network.id

  private_ip_google_access = true
}

# Firewall rules
resource "google_compute_firewall" "allow_proxy_inbound" {
  name    = "${var.deployment_name}-allow-proxy"
  network = google_compute_network.atls_network.name

  allow {
    protocol = "tcp"
    ports    = ["26257"] # CockroachDB/Proxy port
  }

  source_ranges = var.allowed_client_cidrs
  target_tags   = ["atls-proxy"]

  description = "Allow inbound connections to proxy from authorized clients"
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "${var.deployment_name}-allow-ssh"
  network = google_compute_network.atls_network.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.allowed_ssh_cidrs
  target_tags   = ["atls-proxy"]

  description = "Allow SSH access for administration"
}

resource "google_compute_firewall" "deny_external_crdb" {
  name     = "${var.deployment_name}-deny-external-crdb"
  network  = google_compute_network.atls_network.name
  priority = 1000

  deny {
    protocol = "tcp"
    ports    = ["26258", "8081"] # CRDB internal ports
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["atls-proxy"]

  description = "Deny direct external access to CockroachDB"
}

# Service account for the proxy VM
resource "google_service_account" "proxy_sa" {
  account_id   = "${var.deployment_name}-sa"
  display_name = "Attested TLS Proxy Service Account"
  description  = "Service account for proxy VM with minimal permissions"
}

# Grant necessary permissions
resource "google_project_iam_member" "proxy_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.proxy_sa.email}"
}

resource "google_project_iam_member" "proxy_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.proxy_sa.email}"
}

# SEV-SNP Confidential VM
resource "google_compute_instance" "atls_proxy" {
  name         = "${var.deployment_name}-vm"
  machine_type = var.machine_type
  zone         = "${var.region}-a"

  tags = ["atls-proxy"]

  # Boot disk
  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  # Network interface
  network_interface {
    subnetwork = google_compute_subnetwork.atls_subnet.id

    # Assign external IP for client access
    access_config {
      network_tier = "PREMIUM"
    }
  }

  # SEV-SNP Confidential Computing Configuration
  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "SEV_SNP"
  }

  # AMD Milan CPU required for SEV-SNP
  min_cpu_platform = "AMD Milan"

  # Confidential VMs must use TERMINATE maintenance policy
  scheduling {
    on_host_maintenance = "TERMINATE"
    automatic_restart   = true
    preemptible         = false
  }

  # Service account
  service_account {
    email  = google_service_account.proxy_sa.email
    scopes = ["cloud-platform"]
  }

  # Metadata and startup script
  metadata = {
    startup-script = templatefile("${path.module}/startup.sh", {
      project_id   = var.project_id
      region       = var.region
      proxy_config = base64encode(file("${path.module}/../../config/production.yaml"))
    })
    enable-oslogin = "TRUE"
  }

  # Allow VM to be destroyed and recreated
  allow_stopping_for_update = true

  labels = {
    environment = var.environment
    application = "attested-tls-proxy"
    managed-by  = "terraform"
  }
}

# Health check for the proxy
resource "google_compute_health_check" "atls_proxy_health" {
  name                = "${var.deployment_name}-health-check"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = 26257
  }

  description = "Health check for attested TLS proxy"
}

# Outputs
output "proxy_external_ip" {
  description = "External IP address of the proxy"
  value       = google_compute_instance.atls_proxy.network_interface[0].access_config[0].nat_ip
}

output "proxy_internal_ip" {
  description = "Internal IP address of the proxy"
  value       = google_compute_instance.atls_proxy.network_interface[0].network_ip
}

output "ssh_command" {
  description = "Command to SSH into the proxy VM"
  value       = "gcloud compute ssh ${google_compute_instance.atls_proxy.name} --zone=${google_compute_instance.atls_proxy.zone} --project=${var.project_id}"
}

output "connection_string" {
  description = "Connection string for clients to connect through proxy"
  value       = "postgresql://[user]@${google_compute_instance.atls_proxy.network_interface[0].access_config[0].nat_ip}:26257/defaultdb?sslmode=require"
}

output "vm_name" {
  description = "Name of the VM instance"
  value       = google_compute_instance.atls_proxy.name
}

output "service_account_email" {
  description = "Service account email"
  value       = google_service_account.proxy_sa.email
}