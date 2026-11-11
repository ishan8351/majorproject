terraform {
  required_version = ">= 1.0"
}

# --- Multi-Cloud Hybrid Architecture (AWS & GCP) ---

# 1. AWS Cloud Storage Tier
# Compliance Smells: Unencrypted S3 Bucket (CKV_AWS_19), Missing Versioning (CKV_AWS_21)
resource "aws_s3_bucket" "hybrid_sync_bucket" {
  bucket = "multicloud-hybrid-crosscloud-sync-prod"

  tags = {
    Environment = "production"
    Provider    = "AWS"
  }
}

# 2. GCP Compute Network Foundation
resource "google_compute_network" "hybrid_network" {
  name                    = "hybrid-core-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "hybrid_subnetwork" {
  name          = "hybrid-backend-subnet"
  ip_cidr_range = "10.50.0.0/24"
  region        = "us-central1"
  network       = google_compute_network.hybrid_network.id
}

# 3. GCP Perimeter Security
# Compliance Smell: Open SSH Port 22 Ingress (CKV_GCP_2)
resource "google_compute_firewall" "hybrid_firewall" {
  name    = "allow-hybrid-ingress"
  network = google_compute_network.hybrid_network.name

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22", "80"]
  }
}

# 4. GCP Cloud Storage Disaster Recovery Bucket
# Compliance Smell: Uniform Bucket Level Access Disabled (CKV_GCP_29)
resource "google_storage_bucket" "gcp_backup_store" {
  name                        = "multicloud-gcp-disaster-recovery-backup"
  location                    = "US"
  uniform_bucket_level_access = false

  labels = {
    environment = "production"
    provider    = "gcp"
  }
}
