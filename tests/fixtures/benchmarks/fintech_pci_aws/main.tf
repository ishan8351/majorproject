terraform {
  required_version = ">= 1.0"
}

# --- FinTech PCI-DSS AWS Architecture ---

# 1. Foundation Network Tier
resource "aws_vpc" "fintech_vpc" {
  cidr_block           = "10.30.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "fintech-pci-vpc"
    Environment = "production"
    Compliance  = "PCI-DSS"
  }
}

resource "aws_subnet" "app_subnet_1" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.30.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "fintech-app-subnet-1"
  }
}

resource "aws_subnet" "app_subnet_2" {
  vpc_id            = aws_vpc.fintech_vpc.id
  cidr_block        = "10.30.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "fintech-app-subnet-2"
  }
}

# 2. Ingress & Perimeter Security Group
# Statutory Smells:
#   - Open SSH port 22 from 0.0.0.0/0 (CKV_AWS_24)
#   - Missing security group description (CKV_AWS_23)
resource "aws_security_group" "pci_ingress_sg" {
  name   = "fintech-payment-alb-sg"
  vpc_id = aws_vpc.fintech_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.30.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "fintech-alb-sg"
  }
}

# 3. Application Load Balancer
resource "aws_lb" "fintech_alb" {
  name               = "fintech-payment-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.pci_ingress_sg.id]
  subnets            = [aws_subnet.app_subnet_1.id, aws_subnet.app_subnet_2.id]

  tags = {
    Name       = "fintech-payment-alb"
    Compliance = "PCI-DSS"
  }
}

# 4. Storage & Cardholder Data Tier
# Statutory Smell: Unencrypted EBS Volume (CKV_AWS_135)
resource "aws_ebs_volume" "cardholder_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false

  tags = {
    Name       = "pci-transaction-volume"
    Compliance = "PCI-DSS Req 3.4"
  }
}

# Statutory Smell: S3 Credit Card Data unencrypted by KMS (CKV_AWS_145)
resource "aws_s3_bucket" "cardholder_data" {
  bucket = "fintech-pci-cardholder-primary-storage"

  tags = {
    Name       = "pci-cardholder-vault"
    Compliance = "PCI-DSS"
    DataClass  = "PAN"
  }
}

# 5. Containerized Payment Compute Tier
resource "aws_ecs_task_definition" "payment_processor" {
  family                   = "fintech-payment-processor"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"

  container_definitions = <<DEFINITION
[
  {
    "name": "payment-api",
    "image": "fintech/payment-gateway:v2.1",
    "essential": true,
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 8080
      }
    ]
  }
]
DEFINITION
}
