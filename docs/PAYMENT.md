# Payments

Payments are implemented behind a gateway interface.

## Providers

- `mock` (default): always succeeds, credits only after webhook
- `maya` (skeleton): endpoint exists but returns 501 unless implemented

## Flow (mock)

1. Create a checkout:

`POST /api/v1/payments/checkout`

2. Complete by calling the webhook:

`POST /api/v1/payments/webhook/mock`

Requirements:

- Provide an `Idempotency-Key` header (or `ref`) to prevent double-crediting
- Wallet is credited **only** after webhook is accepted

All webhook payloads are stored in `webhook_logs`.

