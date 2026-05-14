# Voucher Management

Phase 2A adds admin-managed vouchers for the Captive Portal direction.

Vouchers are prepaid access codes. In a later phase, customers will enter these codes in the captive portal. In Phase 2A, admins can create, bulk generate, export, disable, void, and test redeem vouchers.

## Voucher Types

- `TIME_BASED`: adds a fixed amount of time to the customer wallet, such as 1 hour or 1 day.
- `DATE_BASED`: grants access until a specific `valid_until` date/time. Redemption extends only when the voucher date is later than the customer's current wallet date.
- `UNLIMITED`: sets the customer wallet to unlimited. It can optionally set a valid-until date for future expiry handling.

## Statuses

- `UNUSED`: can be redeemed.
- `USED`: already redeemed and cannot be reused unless the max redemption count allows it.
- `EXPIRED`: cannot be redeemed.
- `DISABLED`: temporarily blocked by an admin.
- `VOIDED`: permanently invalidated by an admin.

## Wallet Credit Rules

Voucher redemption does not replace the PostgreSQL wallet/session source of truth. A voucher is a credit source.

On successful redemption:
- `TIME_BASED` increases `wallets.time_remaining_seconds`.
- `DATE_BASED` updates `wallets.valid_until` only if the voucher date is later.
- `UNLIMITED` sets `wallets.is_unlimited = true` and can update `wallets.valid_until`.
- A `transactions` row is created with `source = VOUCHER`, `type = CREDIT`, and `reference = voucher code`.
- A `voucher_redemptions` row records the result.

## Creating One Voucher

Open Admin Portal -> Vouchers -> Create Voucher.

Choose the voucher type, enter the value, optionally generate a code, set expiry/note if needed, then create the voucher.

## Bulk Generation

Open Admin Portal -> Vouchers -> Bulk Generate.

Enter a batch name, quantity, voucher type, value, prefix, and code length. Use Preview to inspect code format, then Generate Batch.

## Export and Print

Use Vouchers -> Voucher List or Batches to export CSV. Print uses the browser print dialog with a simple voucher-code layout.

## Test Redemption

Open Vouchers -> Test Redeem.

Select an existing customer/account, enter a voucher code, and run Test Redeem. This is admin validation only. It simulates what the customer portal will do later.

## Client Portal Redemption

Phase 2B adds customer-facing redemption from `/portal`.

Redemption sources:
- `ADMIN_TEST`: admin validation from the Vouchers page.
- `CLIENT_PORTAL`: customer-facing portal redemption.

Client portal redemption creates or reuses an internal portal customer account for the browser/portal session, then credits that account wallet through the same voucher service.

Phase 2C adds Omada captive portal authorization behavior. If the portal session came from Omada query parameters, the voucher is validated first and Omada client authorization is attempted before the voucher is consumed. If authorization fails, the voucher remains unused and the failure is logged under Captive Portal -> Authorization Logs.

## Not Built Yet

Phase 2A does not include:
- Payments.
- SMS.
- Coinslot/vendo integration.

Phase 2C does not include:
- Production rollout to all APs/substations.
- MikroTik hotspot integration.
- Payments.
- SMS.
- Coinslot/vendo integration.
