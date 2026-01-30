#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run as root: sudo ./deploy/install.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
INSTALL_DIR="/opt/centralwifi"
APP_DIR="${INSTALL_DIR}/app"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

rand_hex() { openssl rand -hex "${1:-32}"; }

rand_b64_32() {
  # 32 bytes, urlsafe base64 without trailing '='
  python3 - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
PY
}

get_primary_ip() {
  hostname -I 2>/dev/null | awk '{print $1}' || true
}

echo "[1/6] Installing system dependencies (Docker, UFW, openssl, curl)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release ufw openssl rsync python3 git

if ! need_cmd docker; then
  apt-get install -y docker.io
fi
if ! docker compose version >/dev/null 2>&1; then
  # Ubuntu packages vary by release.
  apt-get install -y docker-compose-v2 >/dev/null 2>&1 || \
  apt-get install -y docker-compose-plugin >/dev/null 2>&1 || \
  apt-get install -y docker-compose
fi
systemctl enable --now docker

echo "[2/6] Installing application to ${APP_DIR} ..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${APP_DIR}"
rsync -a --delete \
  --exclude ".git" \
  --exclude ".env" \
  --exclude ".env.*" \
  --exclude "node_modules" \
  --exclude ".next" \
  --exclude "__pycache__" \
  --exclude "external/juanfi-base" \
  "${REPO_ROOT}/" "${APP_DIR}/"

echo "[2.5/6] Ensuring JuanFi base is cloned (hardware firmware)..."
if [[ ! -d "${APP_DIR}/external/juanfi-base/.git" ]]; then
  # Not required for core RADIUS+wallet runtime, but mandatory for the vendo/coinslot subsystem.
  (cd "${APP_DIR}" && bash scripts/juanfi/clone.sh) || echo "WARN: Failed to clone JuanFi. You can retry later with: (cd ${APP_DIR} && bash scripts/juanfi/clone.sh)" >&2
fi

echo "[3/6] Generating .env (only if missing)..."
ENV_FILE="${APP_DIR}/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  POSTGRES_PASSWORD="$(rand_hex 24)"
  JWT_SECRET="$(rand_hex 32)"
  ADMIN_PASSWORD="$(rand_hex 12)"
  RADIUS_SHARED_SECRET="$(rand_hex 18)"
  DEVICE_TOKEN_ENC_KEY="$(rand_b64_32)"

  CW_DOMAIN=":80"
  IP="$(get_primary_ip)"
  CW_PUBLIC_BASE_URL="http://${IP:-127.0.0.1}"

  cat >"${ENV_FILE}" <<EOF
CW_ENV=production
CW_PUBLIC_BASE_URL=${CW_PUBLIC_BASE_URL}
CW_DOMAIN=${CW_DOMAIN}

POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=centralwifi
POSTGRES_USER=centralwifi
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DATABASE_URL=postgresql+psycopg2://centralwifi:${POSTGRES_PASSWORD}@postgres:5432/centralwifi

REDIS_URL=redis://redis:6379/0

API_PORT=8000
JWT_ISSUER=centralwifi
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRES_SECONDS=86400

ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}

RADIUS_SHARED_SECRET=${RADIUS_SHARED_SECRET}
ACTIVE_SESSION_GRACE_SECONDS=180

VENDO_SECONDS_PER_COIN=300
VENDO_EVENT_TOLERANCE_SECONDS=600
DEVICE_TOKEN_ENC_KEY=${DEVICE_TOKEN_ENC_KEY}

SMS_PROVIDER=mock
PAYMENT_PROVIDER=mock
EOF
  chmod 600 "${ENV_FILE}"
fi

echo "[4/6] Configuring UFW..."
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 1812/udp >/dev/null 2>&1 || true
ufw allow 1813/udp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

echo "[5/6] Starting stack with Docker Compose..."
cd "${APP_DIR}"
docker compose build --pull
# Bring up database/cache first, then apply migrations, then start the full stack.
docker compose up -d postgres redis
timeout 120 bash -lc 'until docker compose exec -T postgres pg_isready -U centralwifi -d centralwifi >/dev/null 2>&1; do sleep 2; done'
docker compose run --rm migrate
docker compose up -d

echo "[6/6] Waiting for services to become healthy..."
# Avoid `docker compose ps --format json` portability issues across compose versions.
timeout 300 bash -lc 'until docker compose exec -T api curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; do sleep 2; done'
timeout 300 bash -lc 'until docker compose exec -T admin curl -fsS http://127.0.0.1/healthz >/dev/null 2>&1; do sleep 2; done'
timeout 300 bash -lc 'until docker compose exec -T radius pgrep freeradius >/dev/null 2>&1; do sleep 2; done'
timeout 300 bash -lc 'until curl -fsS http://127.0.0.1/healthz >/dev/null 2>&1; do sleep 2; done'

source "${ENV_FILE}"
IP="$(get_primary_ip)"
BASE_URL="${CW_PUBLIC_BASE_URL:-http://${IP:-127.0.0.1}}"

echo
echo "Centralized WiFi Roaming Platform is running."
echo "Admin UI: ${BASE_URL}/"
echo "API:      ${BASE_URL}/api/"
echo
echo "Default admin credentials:"
echo "  username: ${ADMIN_USERNAME}"
echo "  password: ${ADMIN_PASSWORD}"
echo
echo "RADIUS shared secret (use for NAS/AP RADIUS config):"
echo "  ${RADIUS_SHARED_SECRET}"
echo
echo "Install location: ${APP_DIR}"
