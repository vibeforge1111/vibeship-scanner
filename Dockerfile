# SvelteKit Frontend Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app

# Copy package files for production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy built application from builder
COPY --from=builder /app/build ./build
COPY --from=builder /app/package.json ./

# Expose port (Railway sets PORT automatically)
ENV PORT=3000
EXPOSE 3000

# Start the server
# adapter-node outputs to build/ directory with index.js
# Railway will set PORT environment variable automatically
CMD ["node", "build/index.js"]

