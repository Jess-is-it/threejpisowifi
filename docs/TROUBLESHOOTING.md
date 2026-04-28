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

Real FreeRADIUS Packet Test notes:
- The internal Admin Portal packet test is sent by the API container, not by a router/AP.
- It must use the internal Docker client `Docker API Test NAS` and the `RADIUS_DEFAULT_SECRET` configured in FreeRADIUS.
- Do not use a router/AP NAS record shared secret for the internal packet test.
- If the result is `No Reply`, check the RADIUS host, UDP port, Docker networking, firewall, and FreeRADIUS container status.
- If the result is `Wrong Secret`, confirm the internal Docker client secret matches `RADIUS_DEFAULT_SECRET`.
- If the result is `Access-Reject`, use the displayed reason and suggestion in the Admin Portal.

Reject reason mapping:
- `Unknown user`: create the user or verify username spelling.
- `Invalid password`: reset the user password and test again.
- `User disabled`: enable the user account.
- `No active wallet balance`: add manual balance or set unlimited access.
- `Account expired`: extend the valid-until date.
- `Active session already exists`: stop the active session or wait for the active session grace window.
- `Database lookup failed`: check API/PostgreSQL/FreeRADIUS database connectivity.
- `Unknown authorization failure`: check FreeRADIUS logs.

Firewall checks:

```bash
sudo ufw status
```

Port conflict checks:

```bash
sudo ss -tulpn | grep -E ':(80|8080|1812|1813|11812|11813)'
```
