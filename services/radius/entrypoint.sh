#!/usr/bin/env bash
set -euo pipefail

POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-centralwifi}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
POSTGRES_DB="${POSTGRES_DB:-centralwifi}"

export PGPASSWORD="${POSTGRES_PASSWORD}"

render() {
  local file="$1"
  shift
  # Replace patterns like %{env:VAR} with concrete values for modules that don't expand xlats in config.
  while [ "$#" -gt 0 ]; do
    local var="$1"; shift
    local val="${!var:-}"
    # Escape sed delimiters.
    val="${val//\\/\\\\}"
    val="${val//|/\\|}"
    sed -i "s|%{env:${var}}|${val}|g" "$file"
  done
}

if [[ -f /etc/freeradius/3.0/mods-enabled/sql ]]; then
  render /etc/freeradius/3.0/mods-enabled/sql POSTGRES_HOST POSTGRES_PORT POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB
fi
if [[ -f /etc/freeradius/3.0/clients.conf ]]; then
  render /etc/freeradius/3.0/clients.conf RADIUS_SHARED_SECRET
fi
if [[ -f /etc/freeradius/3.0/policy.d/centralwifi ]]; then
  render /etc/freeradius/3.0/policy.d/centralwifi ACTIVE_SESSION_GRACE_SECONDS
fi

echo "[radius] waiting for postgres at ${POSTGRES_HOST}:${POSTGRES_PORT}..."
for i in $(seq 1 120); do
  if pg_isready -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[radius] checking required tables/functions..."
for i in $(seq 1 120); do
  ok="1"
  psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name='users' LIMIT 1;" | grep -q 1 || ok="0"
  psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -tAc "SELECT 1 FROM pg_proc WHERE proname='cw_radius_is_allowed' LIMIT 1;" | grep -q 1 || ok="0"
  if [[ "${ok}" == "1" ]]; then
    break
  fi
  sleep 1
done

echo "[radius] starting FreeRADIUS..."
if [[ "$#" -gt 0 ]]; then
  exec "$@"
fi
exec /usr/sbin/freeradius -f -l stdout
