# Variables for Vulnerable Terraform Configuration

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID for EC2 instance"
  type        = string
  default     = "ami-0c55b159cbfafe1f0"  # Ubuntu 20.04 in us-east-1 (may be outdated)
}

# VULNERABILITY: Default values with sensitive information
variable "db_password" {
  description = "Database password"
  type        = string
  default     = "Password123!"
  # sensitive = true (should be set but isn't)
}

variable "admin_password" {
  description = "Admin password"
  type        = string
  default     = "admin123"
  # No validation for password complexity
}
