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

Accounting troubleshooting:
- `No reply from FreeRADIUS`: confirm the target is `radius:1813` for internal UI tests or `SERVER-IP:11813` for staging external tests.
- `Wrong shared secret`: use the internal Docker test client secret for UI tests, or the NAS record secret for real router/AP tests.
- `No matching active session found`: send Accounting Start first or verify username, Calling-Station-ID, and Acct-Session-Id.
- `User not found`: create the user before sending accounting packets.
- `Wallet already empty`: add manual balance or enable unlimited access.
- `Wallet deducted successfully`: confirm the ACCOUNTING DEBIT transaction on the Wallet page.
- `Accounting packet received but ignored`: verify Acct-Status-Type is Start, Interim-Update, or Stop.
- `Database error`: check PostgreSQL health and the FreeRADIUS runtime environment file inside the radius container.

Useful accounting checks:

```bash
docker exec centralwifi_staging-postgres-1 sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT username, acct_status_type, acct_session_id, result, diagnostic_reason, created_at FROM radius_accounting_logs ORDER BY created_at DESC LIMIT 20;"'
```

```bash
docker exec centralwifi_staging-postgres-1 sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT username, acct_session_id, status, last_update_time, stop_time, acct_session_time FROM sessions ORDER BY last_update_time DESC LIMIT 20;"'
```

Firewall checks:

```bash
sudo ufw status
```

Port conflict checks:

```bash
sudo ss -tulpn | grep -E ':(80|8080|1812|1813|11812|11813)'
```
