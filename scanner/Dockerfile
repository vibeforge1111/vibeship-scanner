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
COPY rules/ /scanner/rules/
COPY benchmark/ /scanner/benchmark/
COPY gitleaks.toml /scanner/gitleaks.toml

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 server:app"]
