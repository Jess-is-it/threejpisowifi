#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
TARGET_ENV="${2:-}"
REPO_URL="${CENTRALWIFI_REPO_URL:-https://github.com/Jess-is-it/threejpisowifi.git}"

usage() {
  echo "Usage: sudo ./deploy/install.sh <install|update> <production|staging>"
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
  fi
}

env_config() {
  case "${TARGET_ENV}" in
    production)
      BRANCH="master"
      INSTALL_DIR="/opt/3jcentralpisowifi-production"
      PROJECT_NAME="centralwifi_prod"
      POSTGRES_DB="centralwifi_prod"
      POSTGRES_VOLUME="centralwifi_prod_postgres_data"
      REDIS_VOLUME="centralwifi_prod_redis_data"
      UPLOADS_VOLUME="centralwifi_prod_uploads_data"
      WEB_HTTP_PORT="80"
      WEB_HTTPS_PORT="443"
      RADIUS_AUTH_PORT="1812"
      RADIUS_ACCT_PORT="1813"
      ADMIN_URL="http://SERVER-IP/admin"
      ;;
    staging)
      BRANCH="staging"
      INSTALL_DIR="/opt/3jcentralpisowifi-staging"
      PROJECT_NAME="centralwifi_staging"
      POSTGRES_DB="centralwifi_staging"
      POSTGRES_VOLUME="centralwifi_staging_postgres_data"
      REDIS_VOLUME="centralwifi_staging_redis_data"
      UPLOADS_VOLUME="centralwifi_staging_uploads_data"
      WEB_HTTP_PORT="8080"
      WEB_HTTPS_PORT="8443"
      RADIUS_AUTH_PORT="11812"
      RADIUS_ACCT_PORT="11813"
      ADMIN_URL="http://SERVER-IP:8080/admin"
      ;;
    *)
      usage
      ;;
  esac
}

check_ubuntu() {
  if [[ ! -f /etc/os-release ]]; then
    echo "Unsupported OS. Ubuntu 22.04+ is required."
    exit 1
  fi
  . /etc/os-release
  if [[ "${ID}" != "ubuntu" ]]; then
    echo "Unsupported OS: ${ID}. Ubuntu 22.04+ is required."
    exit 1
  fi
  local major="${VERSION_ID%%.*}"
  if (( major < 22 )); then
    echo "Unsupported Ubuntu version ${VERSION_ID}. Ubuntu 22.04+ is required."
    exit 1
  fi
}

install_prereqs() {
  apt-get update
  apt-get install -y ca-certificates curl git openssl ufw
  if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com | sh
  fi
  if ! docker compose version >/dev/null 2>&1; then
    apt-get install -y docker-compose-plugin
  fi
}

sync_code() {
  mkdir -p "${INSTALL_DIR}"
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    git -C "${INSTALL_DIR}" fetch origin "${BRANCH}"
    git -C "${INSTALL_DIR}" checkout "${BRANCH}"
    git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
    return
  fi

  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || true)"
  local repo_root
  repo_root="$(cd "${script_dir}/.." && pwd 2>/dev/null || true)"
  if [[ -n "${repo_root}" && -d "${repo_root}/.git" ]]; then
    git -C "${repo_root}" archive --format=tar HEAD | tar -x -C "${INSTALL_DIR}"
  else
    rm -rf "${INSTALL_DIR:?}"/*
    git clone --branch "${BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
  fi
}

password_is_strong() {
  local password="$1"
  [[ "${#password}" -ge 12 ]] || return 1
  [[ "${password}" =~ [A-Z] ]] || return 1
  [[ "${password}" =~ [a-z] ]] || return 1
  [[ "${password}" =~ [0-9] ]] || return 1
}

prompt_admin() {
  read -r -p "Create admin username: " ADMIN_USERNAME
  while true; do
    read -r -s -p "Create admin password: " ADMIN_PASSWORD
    echo
    read -r -s -p "Confirm admin password: " ADMIN_PASSWORD_CONFIRM
    echo
    if [[ "${ADMIN_PASSWORD}" != "${ADMIN_PASSWORD_CONFIRM}" ]]; then
      echo "Passwords do not match."
      continue
    fi
    if ! password_is_strong "${ADMIN_PASSWORD}"; then
      echo "Password must be at least 12 characters and include uppercase, lowercase, and a number."
      continue
    fi
    break
  done
}

generate_env() {
  local env_file="${INSTALL_DIR}/.env"
  if [[ -f "${env_file}" ]]; then
    return
  fi
  local postgres_password jwt_secret radius_secret
  postgres_password="$(openssl rand -hex 24)"
  jwt_secret="$(openssl rand -hex 48)"
  radius_secret="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)"
  cat > "${env_file}" <<EOF
APP_ENV=${TARGET_ENV}
APP_NAME=3JCentralPisowifi
INSTALL_DIR=${INSTALL_DIR}
COMPOSE_PROJECT_NAME=${PROJECT_NAME}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=centralwifi
POSTGRES_PASSWORD=${postgres_password}
DATABASE_URL=postgresql://centralwifi:${postgres_password}@postgres:5432/${POSTGRES_DB}
REDIS_URL=redis://redis:6379/0
JWT_SECRET=${jwt_secret}
JWT_EXPIRE_MINUTES=720
ACTIVE_SESSION_GRACE_SECONDS=180
POSTGRES_VOLUME=${POSTGRES_VOLUME}
REDIS_VOLUME=${REDIS_VOLUME}
UPLOADS_VOLUME=${UPLOADS_VOLUME}
WEB_HTTP_PORT=${WEB_HTTP_PORT}
WEB_HTTPS_PORT=${WEB_HTTPS_PORT}
RADIUS_AUTH_PORT=${RADIUS_AUTH_PORT}
RADIUS_ACCT_PORT=${RADIUS_ACCT_PORT}
RADIUS_DEFAULT_SECRET=${radius_secret}
EOF
  chmod 600 "${env_file}"
}

compose() {
  docker compose --env-file "${INSTALL_DIR}/.env" \
    -p "${PROJECT_NAME}" \
    -f "${INSTALL_DIR}/docker-compose.yml" \
    -f "${INSTALL_DIR}/docker-compose.${TARGET_ENV}.yml" "$@"
}

start_services() {
  compose up -d --build postgres redis
  compose build api
  compose run --rm api python -m app.migrate
  compose run --rm api python -m app.seed_admin "${ADMIN_USERNAME}" "${ADMIN_PASSWORD}"
  compose up -d --build
}

configure_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    ufw allow OpenSSH >/dev/null || true
    ufw allow "${WEB_HTTP_PORT}/tcp" >/dev/null || true
    ufw allow "${RADIUS_AUTH_PORT}/udp" >/dev/null || true
    ufw allow "${RADIUS_ACCT_PORT}/udp" >/dev/null || true
    if ufw status | grep -q "Status: active"; then
      ufw reload >/dev/null || true
    fi
  fi
}

backup_before_update() {
  "${INSTALL_DIR}/deploy/backup.sh" "${TARGET_ENV}" || true
}

run_update() {
  if [[ ! -d "${INSTALL_DIR}" ]]; then
    echo "No existing ${TARGET_ENV} install found at ${INSTALL_DIR}."
    exit 1
  fi
  backup_before_update
  sync_code
  generate_env
  compose up -d --build postgres redis
  compose build api
  compose run --rm api python -m app.migrate
  compose up -d --build
  "${INSTALL_DIR}/deploy/healthcheck.sh" "${TARGET_ENV}" || {
    echo "Health checks failed. Restore with: sudo ${INSTALL_DIR}/deploy/restore.sh ${TARGET_ENV} <backup-dir>"
    exit 1
  }
}

success_message() {
  if [[ "${TARGET_ENV}" == "production" ]]; then
    cat <<'EOF'
🎉 3JCentralPisowifi Production is now installed!
Admin Portal:
http://SERVER-IP/admin

Phase 1 is ready for manual RADIUS testing.
EOF
  else
    cat <<'EOF'
🎉 3JCentralPisowifi Staging is now installed!
Admin Portal:
http://SERVER-IP:8080/admin

Phase 1 staging is ready for manual RADIUS testing.
EOF
  fi
}

main() {
  [[ "${ACTION}" == "install" || "${ACTION}" == "update" ]] || usage
  require_root
  env_config
  check_ubuntu
  install_prereqs
  if [[ "${ACTION}" == "install" ]]; then
    sync_code
    generate_env
    prompt_admin
    start_services
    configure_firewall
    "${INSTALL_DIR}/deploy/healthcheck.sh" "${TARGET_ENV}" || true
    success_message
  else
    run_update
    echo "3JCentralPisowifi ${TARGET_ENV} update completed."
  fi
}

main
