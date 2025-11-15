# Vulnerable Terraform Configuration for Security Training
# WARNING: This configuration contains intentional security misconfigurations
# DO NOT use in production!

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # VULNERABILITY 1: Hardcoded AWS credentials
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# VULNERABILITY 2: S3 bucket with public access
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-app-bucket-${random_id.bucket_id.hex}"

  tags = {
    Name        = "Vulnerable App Bucket"
    Environment = "Training"
  }
}

resource "random_id" "bucket_id" {
  byte_length = 8
}

# VULNERABILITY 3: Public ACL on S3 bucket
resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read-write"
}

# VULNERABILITY 4: No encryption for S3 bucket
# Missing aws_s3_bucket_server_side_encryption_configuration

# VULNERABILITY 5: No versioning enabled
# Missing aws_s3_bucket_versioning

# VULNERABILITY 6: S3 bucket policy allowing public access
resource "aws_s3_bucket_policy" "public_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadWrite"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      }
    ]
  })
}

# VULNERABILITY 7: Security group with unrestricted access
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-app-sg"
  description = "Intentionally insecure security group"
  vpc_id      = aws_vpc.main.id

  # Allow all inbound traffic from anywhere
  ingress {
    description = "Allow all inbound"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH open to the world
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # RDP open to the world
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Vulnerable Security Group"
  }
}

# VULNERABILITY 8: VPC with default settings
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "Vulnerable VPC"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public Subnet"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "Vulnerable IGW"
  }
}

# VULNERABILITY 9: EC2 instance with security issues
resource "aws_instance" "vulnerable_app" {
  ami           = var.ami_id
  instance_type = "t2.micro"

  # No encryption for root volume
  root_block_device {
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = true
    # encrypted = false (default, but explicitly showing the vulnerability)
  }

  # VULNERABILITY 10: Instance Metadata Service v1 (IMDSv1) enabled
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # Should be "required" for IMDSv2
  }

  # Attached to vulnerable security group
  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]
  subnet_id              = aws_subnet.public.id

  # VULNERABILITY 11: User data with hardcoded secrets
  user_data = <<-EOF
              #!/bin/bash
              export DB_PASSWORD="SuperSecret123!"
              export API_KEY="sk-1234567890abcdef"
              echo "admin:Password123!" > /home/ubuntu/.credentials

              # Install Docker
              apt-get update
              apt-get install -y docker.io

              # Run vulnerable app
              docker run -d -p 80:5000 vulnerable-flask-app
              EOF

  # VULNERABILITY 12: No monitoring enabled
  monitoring = false

  # VULNERABILITY 13: Public IP assigned
  associate_public_ip_address = true

  tags = {
    Name = "Vulnerable Flask App"
  }
}

# VULNERABILITY 14: IAM role with overly permissive policies
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# VULNERABILITY 15: Overly permissive IAM policy
resource "aws_iam_role_policy" "vulnerable_policy" {
  name = "vulnerable-policy"
  role = aws_iam_role.vulnerable_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:*",
          "iam:*",
          "rds:*",
          "*"
        ]
        Resource = "*"
      }
    ]
  })
}

# VULNERABILITY 16: RDS instance without encryption
resource "aws_db_instance" "vulnerable_db" {
  identifier             = "vulnerable-db"
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t2.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "Password123!"  # Hardcoded password

  # No encryption
  storage_encrypted = false

  # Public access enabled
  publicly_accessible = true

  # No backup retention
  backup_retention_period = 0

  # Skip final snapshot
  skip_final_snapshot = true

  # Attached to vulnerable security group
  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.vulnerable.name

  tags = {
    Name = "Vulnerable Database"
  }
}

resource "aws_db_subnet_group" "vulnerable" {
  name       = "vulnerable-db-subnet"
  subnet_ids = [aws_subnet.public.id]

  tags = {
    Name = "Vulnerable DB subnet group"
  }
}

# VULNERABILITY 17: CloudWatch logs not encrypted
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/aws/vulnerable-app"
  retention_in_days = 1

  # No KMS encryption key specified

  tags = {
    Name = "Vulnerable App Logs"
  }
}

# VULNERABILITY 18: EBS volume without encryption
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "${var.aws_region}a"
  size              = 10

  # No encryption
  encrypted = false

  tags = {
    Name = "Unencrypted Volume"
  }
}

# VULNERABILITY 19: Secrets in outputs
output "database_password" {
  value       = aws_db_instance.vulnerable_db.password
  description = "Database password (EXPOSED!)"
  # sensitive = true (should be set but isn't)
}

output "vulnerable_instance_public_ip" {
  value       = aws_instance.vulnerable_app.public_ip
  description = "Public IP of vulnerable instance"
}
