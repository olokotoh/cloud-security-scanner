# Cloud Security Scanner - Vulnerable Application for Training

⚠️ **WARNING: THIS APPLICATION IS INTENTIONALLY VULNERABLE!** ⚠️

This project contains a deliberately vulnerable Flask application, Dockerfile, and Terraform configuration designed for **security training and educational purposes only**.

**DO NOT deploy this application in any production environment or on public networks!**

## Purpose

This repository serves as a hands-on learning resource for:
- Understanding common web application vulnerabilities
- Learning about Docker security misconfigurations
- Identifying Terraform infrastructure misconfigurations
- Practicing security scanning and vulnerability assessment
- Training security teams and developers on secure coding practices

## Project Structure

```
cloud-security-scanner/
├── app/
│   └── app.py              # Vulnerable Flask application
├── terraform/
│   ├── main.tf             # Terraform configuration with misconfigurations
│   ├── variables.tf        # Variables with hardcoded secrets
│   └── outputs.tf          # Outputs exposing sensitive data
├── Dockerfile              # Insecure Docker configuration
├── requirements.txt        # Python dependencies
├── .dockerignore          # Poorly configured ignore file
└── .gitignore             # Poorly configured ignore file
```

## Vulnerabilities Overview

### Flask Application Vulnerabilities (app/app.py)

#### 1. **SQL Injection** (`/search` endpoint)
- **Location**: `app/app.py:52`
- **Issue**: Direct string concatenation in SQL queries
- **Exploit**: `?q=admin' OR '1'='1`
- **Impact**: Database compromise, data exfiltration

#### 2. **Cross-Site Scripting (XSS)** (`/` endpoint)
- **Location**: `app/app.py:35`
- **Issue**: Unsanitized user input rendered in HTML
- **Exploit**: `?name=<script>alert('XSS')</script>`
- **Impact**: Session hijacking, credential theft

#### 3. **Command Injection** (`/ping` endpoint)
- **Location**: `app/app.py:75`
- **Issue**: User input passed directly to shell commands
- **Exploit**: `?host=127.0.0.1; cat /etc/passwd`
- **Impact**: Remote code execution, system compromise

#### 4. **Missing Authentication** (`/admin` endpoint)
- **Location**: `app/app.py:95`
- **Issue**: No authentication required for admin panel
- **Exploit**: Direct access to `/admin`
- **Impact**: Unauthorized access to sensitive data

#### 5. **Insecure Deserialization** (`/profile` endpoint)
- **Location**: `app/app.py:115`
- **Issue**: Deserializing untrusted pickle data
- **Exploit**: Crafted pickle payload
- **Impact**: Remote code execution

#### 6. **Path Traversal** (`/file` endpoint)
- **Location**: `app/app.py:135`
- **Issue**: No validation of file paths
- **Exploit**: `?name=../../../../etc/passwd`
- **Impact**: Arbitrary file read

#### 7. **Server-Side Request Forgery (SSRF)** (`/fetch` endpoint)
- **Location**: `app/app.py:145`
- **Issue**: No URL validation
- **Exploit**: `?url=file:///etc/passwd` or internal network scanning
- **Impact**: Internal network access, data exfiltration

#### 8. **Hardcoded Credentials**
- **Location**: `app/app.py:18-20`
- **Issue**: Database credentials and API keys in source code
- **Impact**: Credential compromise

#### 9. **Debug Mode Enabled**
- **Location**: `app/app.py:14`
- **Issue**: Flask debug mode enabled in production
- **Impact**: Information disclosure, code execution via debugger

#### 10. **Weak Secret Key**
- **Location**: `app/app.py:12`
- **Issue**: Hardcoded, predictable secret key
- **Impact**: Session token forgery

### Dockerfile Vulnerabilities

#### 1. **Using 'latest' Tag** (Line 6)
- **Issue**: No version pinning
- **Impact**: Unpredictable builds, potential supply chain attacks

#### 2. **Running as Root** (No USER directive)
- **Issue**: Container runs with root privileges
- **Impact**: Container escape, host compromise

#### 3. **Hardcoded Secrets in ENV** (Lines 11-13)
- **Issue**: Secrets in environment variables
- **Impact**: Secret exposure in image layers

#### 4. **Secrets in Build Args** (Lines 16-17)
- **Issue**: AWS credentials in build arguments
- **Impact**: Credentials visible in image history

#### 5. **No Multi-Stage Build**
- **Issue**: Build tools and dependencies in final image
- **Impact**: Larger attack surface

#### 6. **Unnecessary Packages** (Lines 21-27)
- **Issue**: Installing non-essential tools
- **Impact**: Increased attack surface

#### 7. **Overly Permissive File Permissions** (Line 35)
- **Issue**: chmod 777 on application files
- **Impact**: Easy modification by attackers

#### 8. **Credentials File** (Line 38)
- **Issue**: Creating file with hardcoded credentials
- **Impact**: Credential exposure

#### 9. **Exposing Unnecessary Ports** (Lines 41-43)
- **Issue**: SSH, MySQL ports exposed
- **Impact**: Additional attack vectors

#### 10. **Shell Form CMD** (Line 46)
- **Issue**: Using shell form instead of exec form
- **Impact**: Poor signal handling, potential injection

### Terraform Misconfigurations

#### 1. **Hardcoded AWS Credentials** (terraform/main.tf:15-16)
- **Issue**: AWS keys in code
- **Impact**: Credential compromise

#### 2. **Public S3 Bucket** (terraform/main.tf:30-35)
- **Issue**: Public read-write ACL
- **Impact**: Data breach, unauthorized access

#### 3. **No S3 Encryption**
- **Issue**: Missing server-side encryption
- **Impact**: Data exposure

#### 4. **No S3 Versioning**
- **Issue**: No version control for objects
- **Impact**: Data loss, no recovery

#### 5. **Public S3 Bucket Policy** (terraform/main.tf:50-65)
- **Issue**: Allows public access
- **Impact**: Data breach

#### 6. **Open Security Group** (terraform/main.tf:70-105)
- **Issue**: All ports open to 0.0.0.0/0
- **Impact**: Unrestricted network access

#### 7. **SSH/RDP Open to World** (terraform/main.tf:80-95)
- **Issue**: Remote access from any IP
- **Impact**: Brute force attacks

#### 8. **EC2 Without Volume Encryption** (terraform/main.tf:135-141)
- **Issue**: Unencrypted root volume
- **Impact**: Data exposure

#### 9. **IMDSv1 Enabled** (terraform/main.tf:144-147)
- **Issue**: Using IMDSv1 instead of IMDSv2
- **Impact**: SSRF attacks against metadata service

#### 10. **Hardcoded Secrets in User Data** (terraform/main.tf:155-167)
- **Issue**: Secrets in EC2 user data
- **Impact**: Credential exposure

#### 11. **No CloudWatch Monitoring** (terraform/main.tf:170)
- **Issue**: Monitoring disabled
- **Impact**: No visibility into instance behavior

#### 12. **Public IP Assignment** (terraform/main.tf:173)
- **Issue**: EC2 instance publicly accessible
- **Impact**: Direct internet exposure

#### 13. **Overly Permissive IAM Policy** (terraform/main.tf:200-215)
- **Issue**: Wildcard permissions on all resources
- **Impact**: Privilege escalation

#### 14. **RDS Without Encryption** (terraform/main.tf:226)
- **Issue**: Database storage not encrypted
- **Impact**: Data exposure

#### 15. **Publicly Accessible RDS** (terraform/main.tf:229)
- **Issue**: Database exposed to internet
- **Impact**: Unauthorized database access

#### 16. **Hardcoded RDS Password** (terraform/main.tf:224)
- **Issue**: Database password in code
- **Impact**: Credential compromise

#### 17. **No RDS Backups** (terraform/main.tf:232)
- **Issue**: Backup retention set to 0
- **Impact**: No disaster recovery

#### 18. **CloudWatch Logs Not Encrypted** (terraform/main.tf:247)
- **Issue**: No KMS encryption for logs
- **Impact**: Log data exposure

#### 19. **Unencrypted EBS Volume** (terraform/main.tf:259)
- **Issue**: Additional volume without encryption
- **Impact**: Data exposure

#### 20. **Secrets in Outputs** (terraform/outputs.tf:30-35)
- **Issue**: Passwords exposed in outputs
- **Impact**: Credential disclosure

### Configuration File Vulnerabilities

#### .dockerignore
- **Issue**: Doesn't ignore sensitive files (.env, *.pem, *.key, terraform state)
- **Impact**: Secrets included in Docker images

#### .gitignore
- **Issue**: Doesn't ignore sensitive files
- **Impact**: Secrets committed to git repository

## Learning Objectives

### For Security Practitioners:
1. Learn to identify OWASP Top 10 vulnerabilities
2. Practice security scanning and assessment
3. Understand infrastructure misconfigurations
4. Develop remediation strategies

### For Developers:
1. Understand common security pitfalls
2. Learn secure coding practices
3. Understand the importance of security in DevOps
4. Practice secure configuration management

## Recommended Security Scanning Tools

Test your scanning skills with these tools:

### Application Security:
- **Bandit**: Python security linter
- **OWASP ZAP**: Web application security scanner
- **SQLMap**: SQL injection testing
- **Burp Suite**: Web vulnerability scanner

### Container Security:
- **Trivy**: Container vulnerability scanner
- **Hadolint**: Dockerfile linter
- **Docker Bench**: Docker security audit
- **Snyk**: Container and dependency scanning

### Infrastructure Security:
- **tfsec**: Terraform security scanner
- **Checkov**: Infrastructure as code scanner
- **Terrascan**: IaC security scanner
- **AWS Security Hub**: AWS security findings

## How to Use This Repository

### 1. **Static Analysis**
```bash
# Scan Python code
bandit -r app/

# Scan Dockerfile
hadolint Dockerfile

# Scan Terraform
tfsec terraform/
checkov -d terraform/
```

### 2. **Running the Application (Use with caution!)**
```bash
# Build Docker image
docker build -t vulnerable-flask-app .

# Run container (isolated network only!)
docker run -p 5000:5000 vulnerable-flask-app
```

### 3. **Testing Vulnerabilities**
Visit the application endpoints and try the exploits mentioned above.

### 4. **Infrastructure Scanning**
```bash
# Initialize Terraform (don't apply!)
cd terraform
terraform init
terraform plan

# Scan with tools
tfsec .
```

## Remediation Guide

For each vulnerability, practice:
1. Identifying the issue
2. Understanding the impact
3. Implementing the fix
4. Validating the remediation

## Security Best Practices (What NOT to do)

This repository demonstrates what NOT to do. Key takeaways:

### Application Security:
- ✅ Use parameterized queries (not string concatenation)
- ✅ Sanitize all user input
- ✅ Implement proper authentication/authorization
- ✅ Never hardcode credentials
- ✅ Disable debug mode in production
- ✅ Use strong, random secret keys
- ✅ Validate and sanitize file paths
- ✅ Implement input validation

### Container Security:
- ✅ Use specific version tags
- ✅ Run as non-root user
- ✅ Use multi-stage builds
- ✅ Never include secrets in images
- ✅ Use .dockerignore properly
- ✅ Minimize installed packages
- ✅ Use exec form for CMD/ENTRYPOINT
- ✅ Scan images regularly

### Infrastructure Security:
- ✅ Never hardcode credentials
- ✅ Enable encryption at rest and in transit
- ✅ Use least privilege principle for IAM
- ✅ Restrict security groups to necessary ports/IPs
- ✅ Enable monitoring and logging
- ✅ Use IMDSv2 for EC2 instances
- ✅ Enable backups and versioning
- ✅ Mark sensitive outputs as sensitive
- ✅ Use private subnets for databases
- ✅ Regular security scanning

## Disclaimer

This application is provided for educational purposes only. The creators are not responsible for any misuse of this code. Always:
- Use in isolated environments only
- Never deploy to production
- Never expose to public networks
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Contributing

If you find additional vulnerabilities or have suggestions for educational improvements, please submit a pull request or open an issue.

## License

This project is provided as-is for educational purposes.

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Terraform Security Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)

---

**Remember: Security is everyone's responsibility. Learn from these mistakes and build secure systems!**
