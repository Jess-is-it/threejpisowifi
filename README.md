# Centralized WiFi Roaming Platform

Production-ready, one-command deployable system for **centralized WPA2-Enterprise (802.1X) roaming** across multiple substations/sites.

Core principles:

- FreeRADIUS is the **only** authority for access (no captive portal for paid users)
- PostgreSQL is the single source of truth for:
  - users
  - wallet (time/date/unlimited)
  - sessions (single-device enforcement)
  - vendo credits
  - payment webhooks
  - audit logs

## Deploy (Ubuntu 22.04+)

```bash
sudo ./deploy/install.sh
```

Then open the printed Admin URL and login with the printed admin credentials.

## Documentation

See `docs/`:

- `docs/INSTALL.md`
- `docs/OMADA_SETUP.md`
- `docs/RADIUS_TESTING.md`
- `docs/VENDO_INTEGRATION.md`
- `docs/PAYMENT.md`
- `docs/SMS.md`
- `docs/SECURITY.md`

## Quick local validation

```bash
./tests/acceptance.sh
```

Initial repository setup.
