# Vendo / JuanFi Integration (Central Wallet Mode)

This platform **explicitly uses JuanFi as the base** for the coinslot/vendo subsystem.

Repository (upstream): `https://github.com/ivanalayan15/JuanFi.git`

License compliance notes:

- Preserve original JuanFi license notices.
- Treat this as a derivative work for **hardware/firmware only**.
- This platform **does not** create MikroTik Hotspot users and **does not** use RouterOS hotspot time enforcement.

## Repo layout

- `external/juanfi-base` - upstream clone location (not committed; clone via script)
- `docs/VENDO_INTEGRATION.md` - this document

## Clone JuanFi base

From repo root:

```bash
mkdir -p external
git clone https://github.com/ivanalayan15/JuanFi.git external/juanfi-base
```

## Central Wallet Mode requirements

You must add a build flag (or config constant):

- `CENTRAL_WALLET_MODE=true`

And modify the coin insertion flow to call the backend instead of creating MikroTik Hotspot users.

## Backend endpoints (required)

### POST `/api/v1/vendo/credit`

JuanFi firmware sends:

```json
{
  "device_id": "vendo-001",
  "coin_amount": 5,
  "timestamp": 1738180000,
  "nonce": "unique-per-event",
  "hmac_signature": "hex-hmac-sha256",
  "target_phone": "+15551234567"
}
```

Notes:

- `target_phone` is optional; if omitted, the backend credits the wallet bound to the device (`devices.wallet_user_id`).

### POST `/api/v1/vendo/batch-credit`

```json
{ "events": [ { ... }, { ... } ] }
```

## Security model

### HMAC signature

Canonical string:

```
device_id:coin_amount:timestamp:nonce
```

Signature:

- `hex(HMAC_SHA256(device_token, canonical_string))`

### Replay protection / idempotency

- `(device_id, nonce)` is unique in the database (`device_events` table).
- Replays return `{ ok: true, idempotent: true }` without double-crediting.

### Timestamp tolerance

- Events are accepted only within `VENDO_EVENT_TOLERANCE_SECONDS` (default 600s).

## Provisioning a device token

In Admin UI:

- Vendo Devices → Add Device
- Copy the `device_token` shown once and store it in firmware.

The token is stored encrypted server-side (`devices.token_enc`) using `DEVICE_TOKEN_ENC_KEY`.

## Firmware flashing (high-level)

JuanFi is ESP-based. Typical flashing steps:

1. Install PlatformIO (VS Code) or Arduino toolchain depending on your JuanFi build.
2. Configure WiFi SSID/password for the device itself (management).
3. Configure:
   - `DEVICE_ID`
   - `DEVICE_TOKEN`
   - `BACKEND_URL` (https://your-domain)
4. Build and flash using the toolchain supported by your JuanFi version.

## Conversion: coins to seconds

The backend converts coins → wallet time using:

- `VENDO_SECONDS_PER_COIN` (default 300 seconds per coin)

The backend is the **only** authority for conversion.

