FROM node:20-slim

WORKDIR /app

# Install system dependencies and scanning tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Python scanning tools
RUN pip3 install --break-system-packages semgrep

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.48.0

# Install Gitleaks
RUN wget -qO- https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz | tar xz -C /usr/local/bin

# Copy package files
COPY package*.json ./

# Install Node dependencies
RUN npm ci

# Copy source code
COPY . .

# Build SvelteKit app
RUN npm run build

# Expose port
EXPOSE 3000

# Start the app
CMD ["node", "build"]
