# SMS Delivery (Smart A2P Compatible)

SMS delivery is implemented behind a provider interface.

## Providers

- `mock` (default): logs sends to the database (`sms_logs`)
- `smart-a2p` (skeleton): implement env-based credentials + HTTP adapter as needed

## Test tool

Admin UI → SMS Tool

or API:

`POST /api/v1/sms/test` (admin token required)

All sends are logged in `sms_logs`.

