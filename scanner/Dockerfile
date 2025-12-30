FROM python:3.11-slim

WORKDIR /scanner

RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Retire.js for JavaScript library vulnerability scanning
RUN npm install -g retire

# ============================================
# TOOL #5: Bandit - Python Security Linter
# PyCQA - Hardcoded passwords, SQL injection, command injection
# ============================================
RUN pip install bandit

# ============================================
# TOOL #6: Gosec - Go Security Checker
# Inspects Go source code for security problems
# ============================================
RUN curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b /usr/local/bin v2.21.4

# ============================================
# TOOL #7: Hadolint - Dockerfile Linter
# Best practices and security for Dockerfiles
# ============================================
RUN wget -qO /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 \
    && chmod +x /usr/local/bin/hadolint

# ============================================
# TOOL #8: Checkov - IaC Security Scanner
# Terraform, Kubernetes, Docker, CloudFormation
# ============================================
RUN pip install checkov

# ============================================
# TOOL #9: Brakeman - Ruby/Rails Security Scanner
# SQL injection, XSS, command injection in Rails
# ============================================
RUN apt-get update && apt-get install -y ruby ruby-dev build-essential \
    && gem install brakeman --no-document \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ============================================
# TOOL #10: Slither - Solidity Static Analyzer
# Smart contract vulnerabilities, reentrancy, etc.
# ============================================
RUN pip install slither-analyzer

# Install Opengrep (LGPL fork of Semgrep - avoids commercial licensing issues)
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash \
    && ln -s ~/.opengrep/cli/latest/opengrep /usr/local/bin/opengrep

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.56.0

# Pre-download Trivy vulnerability database during build
RUN trivy fs --download-db-only

RUN wget -qO- https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz | tar xz -C /usr/local/bin

COPY requirements.txt /scanner/requirements.txt
RUN pip install -r requirements.txt

COPY scan.py /scanner/scan.py
COPY server.py /scanner/server.py
COPY mcp_endpoint.py /scanner/mcp_endpoint.py
COPY rules/ /scanner/rules/
COPY gitleaks.toml /scanner/gitleaks.toml
COPY feedback/ /scanner/feedback/

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 server:app"]
