# ─────────────────────────────────────────────────────────────
# Secure Dockerfile — all VULN-12 issues remediated:
#   a) Up-to-date LTS base image (node:20-alpine)
#   b) No secrets baked into image layers
#   c) Non-root user
#   d) HEALTHCHECK defined
#   e) .dockerignore prevents sensitive files from being copied
# ─────────────────────────────────────────────────────────────

FROM node:22-alpine

WORKDIR /app

# Copy dependency manifests first (better layer caching)
COPY package*.json ./

RUN npm ci --omit=dev

# Copy application code (ensure .dockerignore excludes .env)
COPY . .

# FIX for VULN-12c: run as a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 3000

# FIX for VULN-12d: HEALTHCHECK defined
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
