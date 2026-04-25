#!/usr/bin/env bash
set -euo pipefail

TARGET_ENV="${1:-}"
BACKUP_DIR="${2:-}"
case "${TARGET_ENV}" in
  production) INSTALL_DIR="/opt/3jcentralpisowifi-production"; PROJECT_NAME="centralwifi_prod" ;;
  staging) INSTALL_DIR="/opt/3jcentralpisowifi-staging"; PROJECT_NAME="centralwifi_staging" ;;
  *) echo "Usage: sudo ./deploy/restore.sh <production|staging> <backup-dir>"; exit 1 ;;
esac

if [[ ! -d "${BACKUP_DIR}" ]]; then
  echo "Backup directory not found: ${BACKUP_DIR}"
  exit 1
fi

cp -a "${BACKUP_DIR}/.env" "${INSTALL_DIR}/.env" 2>/dev/null || true
set -a
# shellcheck disable=SC1091
source "${INSTALL_DIR}/.env"
set +a
docker compose --env-file "${INSTALL_DIR}/.env" -p "${PROJECT_NAME}" \
  -f "${INSTALL_DIR}/docker-compose.yml" -f "${INSTALL_DIR}/docker-compose.${TARGET_ENV}.yml" up -d postgres

if [[ -f "${BACKUP_DIR}/database.sql" ]]; then
  docker compose --env-file "${INSTALL_DIR}/.env" -p "${PROJECT_NAME}" \
    -f "${INSTALL_DIR}/docker-compose.yml" -f "${INSTALL_DIR}/docker-compose.${TARGET_ENV}.yml" \
    exec -T postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" < "${BACKUP_DIR}/database.sql"
fi

docker compose --env-file "${INSTALL_DIR}/.env" -p "${PROJECT_NAME}" \
  -f "${INSTALL_DIR}/docker-compose.yml" -f "${INSTALL_DIR}/docker-compose.${TARGET_ENV}.yml" up -d
echo "Restore completed for ${TARGET_ENV}."
