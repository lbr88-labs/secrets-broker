#!/bin/sh
set -eu

export HOME="${HOME:-/data/home}"
mkdir -p "$HOME" "${SECRETS_BROKER_HOME:-/data}"
chmod 700 "$HOME" "${SECRETS_BROKER_HOME:-/data}" 2>/dev/null || true

# Persist the Bitwarden CLI server setting and API-key login in /data/home.
if [ -n "${BW_SERVER:-}" ]; then
  timeout 20 bw config server "$BW_SERVER" || true
fi
if [ -n "${BW_CLIENTID:-}" ] && [ -n "${BW_CLIENTSECRET:-}" ]; then
  timeout 45 bw login --apikey || true
fi

# Auto-unlock is handled inside server.mjs (it can decrypt /data/master-password).
exec node /app/server.mjs
