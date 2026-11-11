terraform {
  required_version = ">= 1.0"
}

# --- Healthcare HIPAA AWS Multi-Tier Architecture ---

# 1. Foundation Network Tier (Root Resource)
resource "aws_vpc" "hipaa_vpc" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "hipaa-core-vpc"
    Environment = "production"
    Compliance  = "HIPAA"
  }
}

resource "aws_subnet" "hipaa_db_subnet_a" {
  vpc_id            = aws_vpc.hipaa_vpc.id
  cidr_block        = "10.20.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "hipaa-private-db-a"
  }
}

resource "aws_subnet" "hipaa_db_subnet_b" {
  vpc_id            = aws_vpc.hipaa_vpc.id
  cidr_block        = "10.20.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "hipaa-private-db-b"
  }
}

resource "aws_db_subnet_group" "hipaa_db_subnets" {
  name       = "hipaa-db-subnets"
  subnet_ids = [aws_subnet.hipaa_db_subnet_a.id, aws_subnet.hipaa_db_subnet_b.id]

  tags = {
    Name = "hipaa-db-subnet-group"
  }
}

# 2. Cryptographic Tier
resource "aws_kms_key" "hipaa_cmk" {
  description             = "Customer Managed Key for HIPAA patient records"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Compliance = "HIPAA §164.312(a)(2)(iv)"
  }
}

# 3. Patient Database Tier
# Statutory Smell: RDS Storage Unencrypted (CKV_AWS_16)
resource "aws_db_instance" "patient_db" {
  allocated_storage      = 50
  engine                 = "postgres"
  engine_version         = "14.7"
  instance_class         = "db.t3.medium"
  db_name                = "patientrecords"
  username               = "hipaaadmin"
  password               = "SuperSecretHospital2026!"
  db_subnet_group_name   = aws_db_subnet_group.hipaa_db_subnets.name
  skip_final_snapshot    = true
  storage_encrypted      = false

  tags = {
    Name       = "hipaa-ehr-postgresql"
    Compliance = "HIPAA"
  }
}

# 4. Patient Object Storage Tier
# Statutory Smells:
#   - S3 Bucket Unencrypted (CKV_AWS_19)
#   - S3 Bucket Missing Versioning (CKV_AWS_21)
resource "aws_s3_bucket" "patient_records" {
  bucket = "healthcare-corp-patient-records-prod"

  tags = {
    Name       = "hipaa-patient-records"
    Compliance = "HIPAA"
    DataType   = "ePHI"
  }
}

# 5. Statutory Audit Logging Tier
# Statutory Smell: CloudTrail Missing KMS Encryption (CKV_AWS_36)
resource "aws_cloudtrail" "hipaa_audit_trail" {
  name                          = "hipaa-ehr-access-audit-trail"
  s3_bucket_name                = aws_s3_bucket.patient_records.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  tags = {
    Name       = "hipaa-audit-trail"
    Compliance = "HIPAA §164.312(b)"
  }
}

# 6. Statutory IAM Authorization Tier
# Statutory Smell: Wildcard IAM Administrative Policy (CKV_AWS_40)
resource "aws_iam_policy" "wildcard_admin_policy" {
  name        = "hipaa-unconstrained-access-policy"
  description = "Excessive wildcard IAM policy granting full admin access without constraints"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
