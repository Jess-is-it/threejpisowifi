#!/usr/bin/env bash
set -euo pipefail

TARGET_ENV="${1:-}"
case "${TARGET_ENV}" in
  production) INSTALL_DIR="/opt/3jcentralpisowifi-production"; PROJECT_NAME="centralwifi_prod"; WEB_PORT="80" ;;
  staging) INSTALL_DIR="/opt/3jcentralpisowifi-staging"; PROJECT_NAME="centralwifi_staging"; WEB_PORT="8080" ;;
  *) echo "Usage: sudo ./deploy/healthcheck.sh <production|staging>"; exit 1 ;;
esac

docker compose --env-file "${INSTALL_DIR}/.env" -p "${PROJECT_NAME}" \
  -f "${INSTALL_DIR}/docker-compose.yml" -f "${INSTALL_DIR}/docker-compose.${TARGET_ENV}.yml" ps

curl -fsS "http://127.0.0.1:${WEB_PORT}/health" >/dev/null
echo "Healthcheck passed for ${TARGET_ENV}."
