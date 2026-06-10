# syntax=docker/dockerfile:1.7

# ─── Builder ───────────────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS builder

WORKDIR /app

# Build tools needed if better-sqlite3 can't find a prebuilt binary
# (npm install prefers prebuilt, falls back to compile from source).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Install all deps (dev + prod) for the build step.
COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY tsconfig.json tsconfig.server.json tsconfig.client.json vite.config.ts ./
COPY src ./src

RUN npm run build

# Drop devDeps from the node_modules tree we'll copy into the runtime image.
RUN npm prune --omit=dev


# ─── Runtime ───────────────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS runtime

WORKDIR /app
ENV NODE_ENV=production

# Runtime deps:
#   - openssl: auto-generate a self-signed cert at first boot (turnkey),
#   - gosu:    drop privileges from the root entrypoint to the app user.
# The unprivileged `solo` user (uid 10001) is created but NOT set via USER:
# the entrypoint starts as root (to chown bind-mounts / write the cert) and
# execs `gosu solo` so the Node process itself never runs as root.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl gosu ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 -m solo \
 && mkdir -p /data /certs /db \
 && chown -R solo:solo /app /data /certs /db

COPY --from=builder --chown=solo:solo /app/node_modules ./node_modules
COPY --from=builder --chown=solo:solo /app/dist ./dist
COPY --from=builder --chown=solo:solo /app/package.json ./package.json
COPY entrypoint.sh /entrypoint.sh
# Strip any CRLF (repo checked out on Windows with autocrlf=true) so the shebang
# resolves inside the Linux container, then make it executable. Sans ça :
# `exec /entrypoint.sh: no such file or directory`.
RUN sed -i 's/\r$//' /entrypoint.sh && chmod 0755 /entrypoint.sh

EXPOSE 8443

ENV PORT=8443 \
    HOST=0.0.0.0 \
    APP_UID=10001 \
    APP_GID=10001 \
    CERT_PATH=/certs/cert.pem \
    KEY_PATH=/certs/key.pem \
    GEOIP_DB=/data/GeoLite2-ASN.mmdb \
    GEOIP_COUNTRY_DB=/data/GeoLite2-Country.mmdb \
    TOR_EXIT_LIST=/data/tor-exit-nodes.txt \
    DB_PATH=/db/solo.db

ENTRYPOINT ["/entrypoint.sh"]
