# Security

## Access control (authoritative)

- FreeRADIUS makes the final accept/reject decision.
- RADIUS consults PostgreSQL for:
  - user status
  - wallet eligibility
  - active session enforcement (single-device)

## Single-device enforcement

Definition of an active session:

- `stop IS NULL`
- `last_update >= now() - ACTIVE_SESSION_GRACE_SECONDS`

New session attempts are rejected if an active session exists for the same user with a different `calling_station_id`.

Roaming is allowed for the same device (same MAC / `Calling-Station-Id`).

## Wallet debit safety

Wallet time debit is done inside PostgreSQL in one transaction:

- Lock session row
- Lock wallet row
- Compute delta between now and previous `last_update`
- Decrement `time_remaining_seconds` atomically (never below 0)

## Secrets

Secrets are generated at install time and stored in `/opt/centralwifi/app/.env` (mode 600).

Key secrets:

- `JWT_SECRET`
- `RADIUS_SHARED_SECRET`
- `DEVICE_TOKEN_ENC_KEY` (AES-GCM key for device tokens)

## Network hardening

The installer configures UFW for:

- 80/tcp, 443/tcp
- 1812/udp, 1813/udp

Keep SSH allowed (`ufw allow OpenSSH`) before enabling UFW.

## Recommended production additions

- Configure `CW_DOMAIN` and enable HTTPS via Caddy (Let’s Encrypt)
- Backups for PostgreSQL volumes
- Monitoring (container health, RADIUS logs, auth reject rates)

