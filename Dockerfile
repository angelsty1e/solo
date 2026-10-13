# syntax=docker/dockerfile:1.7

# Base image, single source of truth for BOTH stages (no builder/runtime drift).
# Pin by digest for reproducible builds + a frozen OS-CVE surface (audit I1):
# replace the tag below with the tag@sha256:<digest> reported by
#   docker buildx imagetools inspect node:22-bookworm-slim
# (pin the top-level multi-arch index digest so the right arch is still selected).
# Until pinned, the mutable tag is used — overridable at build time with
#   docker build --build-arg NODE_IMAGE=node:22-bookworm-slim@sha256:<digest> .
# Node 22 minimum: pnpm 11 refuses to run below Node 22.13.
ARG NODE_IMAGE=node:22-bookworm-slim

# ─── Builder ───────────────────────────────────────────────────────────────
FROM ${NODE_IMAGE} AS builder

WORKDIR /app

# Build tools needed if better-sqlite3 can't find a prebuilt binary
# (its install script prefers prebuilt, falls back to compile from source).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# pnpm at the exact version pinned by `packageManager` in package.json.
# The store lives in a BuildKit cache mount (/pnpm/store), set once for every
# step so `prune` reuses it instead of re-downloading.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && pnpm config set --global store-dir /pnpm/store

# Install all deps (dev + prod) for the build step, strictly from the lockfile.
# pnpm-workspace.yaml carries `allowBuilds` (better-sqlite3, esbuild): without
# it pnpm 11 skips their install scripts and the native binary is missing.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/pnpm/store \
    pnpm install --frozen-lockfile

COPY tsconfig.json tsconfig.server.json tsconfig.client.json vite.config.ts ./
COPY src ./src

RUN pnpm run build

# Drop devDeps from the node_modules tree we'll copy into the runtime image.
# pnpm rebuilds node_modules for the prod-only set and asks to confirm the purge;
# CI=true answers it (no TTY in a build) — reinstall comes from the cached store.
RUN --mount=type=cache,target=/pnpm/store \
    CI=true pnpm prune --prod


# ─── Runtime ───────────────────────────────────────────────────────────────
FROM ${NODE_IMAGE} AS runtime

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
