# Outputs for Vulnerable Terraform Configuration
# WARNING: These outputs expose sensitive information!

output "s3_bucket_name" {
  value       = aws_s3_bucket.vulnerable_bucket.id
  description = "Name of the S3 bucket"
}

output "s3_bucket_arn" {
  value       = aws_s3_bucket.vulnerable_bucket.arn
  description = "ARN of the S3 bucket"
}

output "ec2_instance_id" {
  value       = aws_instance.vulnerable_app.id
  description = "ID of the EC2 instance"
}

output "ec2_public_ip" {
  value       = aws_instance.vulnerable_app.public_ip
  description = "Public IP address of the EC2 instance"
}

# VULNERABILITY: Exposing sensitive information in outputs
output "db_endpoint" {
  value       = aws_db_instance.vulnerable_db.endpoint
  description = "Database endpoint"
}

output "db_username" {
  value       = aws_db_instance.vulnerable_db.username
  description = "Database username (EXPOSED!)"
  # sensitive = false (default)
}

output "db_password_exposed" {
  value       = var.db_password
  description = "Database password - THIS SHOULD NEVER BE DONE!"
  # sensitive = false
}

output "security_group_id" {
  value       = aws_security_group.vulnerable_sg.id
  description = "ID of the security group"
}

output "vpc_id" {
  value       = aws_vpc.main.id
  description = "ID of the VPC"
}
