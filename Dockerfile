# Vulnerable Dockerfile for Security Training
# WARNING: This Dockerfile contains intentional security issues
# DO NOT use in production!

# VULNERABILITY 1: Using 'latest' tag instead of specific version
FROM python:latest

# VULNERABILITY 2: Running as root user (no USER directive)

# VULNERABILITY 3: Hardcoded secrets in environment variables
ENV DB_PASSWORD=SuperSecret123!
ENV API_KEY=sk-1234567890abcdef
ENV SECRET_KEY=my_flask_secret_key

# VULNERABILITY 4: Exposing sensitive information in build args
ARG AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ARG AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# VULNERABILITY 5: Not using multi-stage builds (larger attack surface)
# VULNERABILITY 6: Installing unnecessary packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    netcat \
    telnet \
    ftp \
    && rm -rf /var/lib/apt/lists/*

# VULNERABILITY 7: Copying entire context (may include secrets)
WORKDIR /app
COPY . /app

# VULNERABILITY 8: Installing packages without verifying integrity
RUN pip install --no-cache-dir -r requirements.txt

# VULNERABILITY 9: Setting overly permissive file permissions
RUN chmod -R 777 /app

# VULNERABILITY 10: Hardcoded credentials in a file
RUN echo "admin:Password123!" > /app/.credentials

# VULNERABILITY 11: Exposing unnecessary ports
EXPOSE 5000
EXPOSE 22
EXPOSE 3306

# VULNERABILITY 12: Using shell form of CMD (vulnerable to signal handling issues)
CMD python app/app.py

# Additional security issues:
# - No health check defined
# - No resource limits
# - No security options (--security-opt)
# - No read-only root filesystem
# - No dropping of capabilities
# - Debug mode enabled in application
