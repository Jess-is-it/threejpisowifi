# Troubleshooting

Check Docker services:

```bash
docker compose --env-file /opt/3jcentralpisowifi-staging/.env -p centralwifi_staging -f /opt/3jcentralpisowifi-staging/docker-compose.yml -f /opt/3jcentralpisowifi-staging/docker-compose.staging.yml ps
```

Check API health:

```bash
curl http://127.0.0.1:8080/health
```

Check FreeRADIUS logs:

```bash
docker logs centralwifi_staging-radius-1
```

Check PostgreSQL logs:

```bash
docker logs centralwifi_staging-postgres-1
```

Common auth failure reasons:
- User does not exist.
- Wrong password.
- User is disabled.
- Manual balance is empty or expired.
- Same account already has an active session.
- Router/AP uses the wrong shared secret.
- Router/AP points to the wrong production or staging port.

Firewall checks:

```bash
sudo ufw status
```

Port conflict checks:

```bash
sudo ss -tulpn | grep -E ':(80|8080|1812|1813|11812|11813)'
```
