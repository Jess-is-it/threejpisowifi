# Centralized WiFi Roaming Platform - Install (Ubuntu 22.04+)

This repo deploys a complete, end-to-end stack:

- FreeRADIUS 3.x (authoritative access control) + PostgreSQL wallet/session logic
- Central Backend API (wallet, admin APIs, vendo credit, mock payment, mock SMS)
- Admin Web UI (static SPA)
- Redis (rate-limit / future queue usage)
- Caddy reverse proxy (routes `/api/*` to the API and `/` to the Admin UI)

## One-command install

On an Ubuntu 22.04+ server:

```bash
git clone <this-repo>
cd <this-repo>
sudo ./deploy/install.sh
```

The installer will:

- Install Docker + Compose if missing
- Create `/opt/centralwifi/app`
- Generate a secure `.env` (random secrets) if missing
- Build and start the full Docker Compose stack
- Configure UFW:
  - 80/tcp
  - 443/tcp
  - 1812/udp (RADIUS auth)
  - 1813/udp (RADIUS accounting)
- Print:
  - Admin URL
  - Default admin credentials
  - RADIUS shared secret

## Post-install

1. Open the Admin UI URL printed by the installer.
2. Login as `admin` using the printed password.
3. Create a WiFi user (phone number in E.164) and credit time.
4. Configure Omada to use WPA2-Enterprise with the printed RADIUS shared secret.

## Update / redeploy

```bash
cd /opt/centralwifi/app
docker compose pull
docker compose up -d --build
```

## Uninstall

```bash
cd /opt/centralwifi/app
docker compose down -v
```

