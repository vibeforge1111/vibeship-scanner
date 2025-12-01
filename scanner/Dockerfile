FROM python:3.11-slim

WORKDIR /scanner

RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN pip install semgrep

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.48.0

RUN wget -qO- https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz | tar xz -C /usr/local/bin

COPY scan.py /scanner/scan.py
COPY rules/ /scanner/rules/
COPY gitleaks.toml /scanner/gitleaks.toml

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "/scanner/scan.py"]
