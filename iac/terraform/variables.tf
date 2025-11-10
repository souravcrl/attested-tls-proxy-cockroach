variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region for deployment"
  type        = string
  default     = "us-central1"
}

variable "deployment_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "atls-proxy"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "machine_type" {
  description = "GCP machine type (must support SEV-SNP: n2d family)"
  type        = string
  default     = "n2d-standard-8"

  validation {
    condition     = can(regex("^n2d-", var.machine_type))
    error_message = "Machine type must be n2d family (AMD Milan) for SEV-SNP support."
  }
}

variable "boot_image" {
  description = "Boot image for the VM"
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
}

variable "boot_disk_size_gb" {
  description = "Size of boot disk in GB (needs space for CRDB data)"
  type        = number
  default     = 100
}

variable "subnet_cidr" {
  description = "CIDR range for the subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "allowed_client_cidrs" {
  description = "List of CIDR ranges allowed to connect to the proxy"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this in production!
}

variable "allowed_ssh_cidrs" {
  description = "List of CIDR ranges allowed to SSH into the VM"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this in production!
}