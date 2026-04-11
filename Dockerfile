# ─────────────────────────────────────────────────────────────
# VULN-12 — Insecure Dockerfile (CWE-250, CWE-798, CWE-1188)
#
#  a) EOL base image (node:14) has hundreds of known OS CVEs
#  b) Secrets baked into image layers via ENV
#  c) App runs as root (no USER directive)
#  d) No HEALTHCHECK
#  e) COPY . . brings in any local .env or sensitive files
# ─────────────────────────────────────────────────────────────

# VULN-12a: node:14 reached End-of-Life April 2023; riddled with CVEs
FROM node:14

WORKDIR /app

# VULN-12b: secrets baked into every image layer — extractable with `docker history`
ENV JWT_SECRET=supersecret123
ENV ADMIN_KEY=admin-key-2024-abc
ENV DB_PASSWORD=P@ssw0rd123!
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# VULN-12e: copies everything, potentially including .env files
COPY . .

RUN npm install --production

EXPOSE 3000

# VULN-12c: no USER directive → process runs as root inside the container
# VULN-12d: no HEALTHCHECK
CMD ["node", "server.js"]
