#!/bin/sh
# First boot on any machine: writable data volume, stable token, no host paths.
set -eu

mkdir -p /data
chown -R aegis:aegis /data

if [ -z "${AEGIS_API_TOKEN:-}" ] && [ -f /data/aegis.token ]; then
  AEGIS_API_TOKEN=$(tr -d '\r\n' < /data/aegis.token)
  export AEGIS_API_TOKEN
fi

cd /app/gateway
exec runuser --preserve-environment -u aegis -- node src/index.js
