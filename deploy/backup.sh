#!/usr/bin/env bash
set -euo pipefail

TARGET_ENV="${1:-}"
case "${TARGET_ENV}" in
  production) INSTALL_DIR="/opt/3jcentralpisowifi-production"; PROJECT_NAME="centralwifi_prod" ;;
  staging) INSTALL_DIR="/opt/3jcentralpisowifi-staging"; PROJECT_NAME="centralwifi_staging" ;;
  *) echo "Usage: sudo ./deploy/backup.sh <production|staging>"; exit 1 ;;
esac

BACKUP_DIR="${INSTALL_DIR}/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${BACKUP_DIR}"
set -a
# shellcheck disable=SC1091
source "${INSTALL_DIR}/.env"
set +a

cp -a "${INSTALL_DIR}/.env" "${BACKUP_DIR}/.env" 2>/dev/null || true
cp -a "${INSTALL_DIR}"/docker-compose*.yml "${BACKUP_DIR}/" 2>/dev/null || true

if docker ps --format '{{.Names}}' | grep -q "${PROJECT_NAME}-postgres"; then
  docker compose --env-file "${INSTALL_DIR}/.env" -p "${PROJECT_NAME}" \
    -f "${INSTALL_DIR}/docker-compose.yml" -f "${INSTALL_DIR}/docker-compose.${TARGET_ENV}.yml" \
    exec -T postgres pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" > "${BACKUP_DIR}/database.sql" || true
fi

echo "${BACKUP_DIR}"
