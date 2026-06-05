#!/bin/sh
# ─── solo entrypoint ─────────────────────────────────────────────────────────
# Makes `docker compose up -d` truly turnkey:
#   1. generate a self-signed TLS certificate if none is provided,
#   2. fix ownership of the (possibly root-owned) bind-mounts,
#   3. drop privileges to the unprivileged app user and exec node.
# Runs as root so it can chown/openssl; the Node process never runs as root.
set -e

CERT_PATH="${CERT_PATH:-/certs/cert.pem}"
KEY_PATH="${KEY_PATH:-/certs/key.pem}"
DB_PATH="${DB_PATH:-/data/solo.db}"
DATA_DIR="$(dirname "$DB_PATH")"
CERT_DIR="$(dirname "$CERT_PATH")"
APP_UID="${APP_UID:-10001}"
APP_GID="${APP_GID:-10001}"
TLS_CN="${TLS_CN:-localhost}"

# TLS_CN is interpolated into openssl's -subj and -addext arguments. Restrict it
# to hostname-safe characters (letters, digits, dot, hyphen) so a hostile value
# can't inject extra openssl options or subject fields. Anything else → reject.
case "$TLS_CN" in
  '' | *[!a-zA-Z0-9.-]*)
    echo "[entrypoint] WARN: TLS_CN '$TLS_CN' is not hostname-safe; falling back to 'localhost'." >&2
    TLS_CN="localhost"
    ;;
esac

mkdir -p "$CERT_DIR" "$DATA_DIR"

# 1. Self-signed certificate if the operator did not provide one.
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
  echo "[entrypoint] No TLS material found — generating a self-signed certificate (CN=$TLS_CN)."
  # Tighten umask in a subshell *before* openssl writes the key, so the private
  # key is created 0600 atomically — never exposed under the default umask, not
  # even for the moment between write and a later chmod. The subshell keeps the
  # restrictive umask from leaking to the rest of the entrypoint.
  (
    umask 0077
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$KEY_PATH" -out "$CERT_PATH" \
      -days 825 -subj "/CN=$TLS_CN" \
      -addext "subjectAltName=DNS:localhost,DNS:$TLS_CN,IP:127.0.0.1,IP:::1" 2>/dev/null
  )
  echo "[entrypoint] Self-signed certificate written to $CERT_PATH"
fi

# 2. Make the writable paths owned by the runtime user. Bind-mounts created by
#    the Docker daemon land as root:root; an operator-supplied read-only cert
#    will fail the chown harmlessly (|| true).
chmod 600 "$KEY_PATH" 2>/dev/null || true
chown -R "$APP_UID:$APP_GID" "$DATA_DIR" 2>/dev/null || true
chown "$APP_UID:$APP_GID" "$CERT_PATH" "$KEY_PATH" 2>/dev/null || true

# 3. Fail-fast on an insecure private key. If ./certs is mounted read-only the
#    chmod above is a silent no-op, so verify the *actual* perms rather than
#    trusting the chmod: a group/other-readable key must never reach the network.
KEY_PERMS="$(stat -c '%a' "$KEY_PATH" 2>/dev/null || echo '???')"
case "$KEY_PERMS" in
  600 | 400) ;; # owner-only read(+write) — OK
  *)
    echo "[entrypoint] FATAL: private key $KEY_PATH has insecure permissions ($KEY_PERMS, expected 600)." >&2
    echo "[entrypoint] Refusing to start. Fix the perms (chmod 600) or remount ./certs writable." >&2
    exit 1
    ;;
esac

# 4. Drop privileges and run the server.
echo "[entrypoint] Starting solo as uid $APP_UID:$APP_GID"
exec gosu "$APP_UID:$APP_GID" node dist/server/index.js
