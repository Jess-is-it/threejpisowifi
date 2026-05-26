# Deployment Environments

3JCentralPisowifi supports staging and production Docker Compose overlays.

## Production

- Web/proxy: `80/tcp`
- API: internal container network
- PostgreSQL: internal container network
- Redis: internal container network
- Uploads: Docker volume

## Staging

- Web/proxy: `8080/tcp`
- API: internal container network
- PostgreSQL: internal container network
- Redis: internal container network
- Uploads: Docker volume

## Removed Runtime

FreeRADIUS is no longer started by the active compose files. RADIUS auth/accounting ports are not published in staging or production.

## Current External Dependencies

- Omada Controller: `192.168.50.71`
- 3JCentralPisowifi portal: `192.168.50.70`
- MikroTik RouterOS API on configured routers for reviewed station transport changes and read-only scans
