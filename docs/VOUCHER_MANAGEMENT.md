# Voucher Management

Vouchers are now an optional access path for events, refunds, welcome gifts, and operator-issued promos. They are no longer the primary purchase flow and they do not credit a Wallet.

Primary customer purchases use Product Items, PayMongo, or Physical Store approvals. Successful voucher claims create customer WiFi Bag items, using the same access model as paid products.

## Voucher Types

- `TIME_BASED`: creates a WiFi Bag item with a fixed duration, such as 1 hour or 1 day.
- `DATE_BASED`: creates access that is valid until a configured date/time where supported by the current portal flow.
- `UNLIMITED`: creates an unlimited access item where supported by the current portal flow.

## Statuses

- `UNUSED`: can be claimed.
- `USED`: already claimed and cannot be reused unless the max redemption count allows it.
- `EXPIRED`: cannot be claimed.
- `DISABLED`: temporarily blocked by an admin.
- `VOIDED`: permanently invalidated by an admin.

## WiFi Bag Claim Rules

On successful redemption:

- A `voucher_redemptions` row records the attempt/result.
- A customer WiFi Bag item is created for the verified portal customer/device.
- Access is authorized through Omada when the customer is connected through a supported Omada captive portal session.
- Wallet tables are not used. Do not reintroduce `wallets`, `transactions`, or Wallet / Manual Top-Up logic.

## Admin Workflow

Open Admin Portal -> Vouchers.

Admins can generate vouchers for special events, customer support, refunds, or welcome gifts. Voucher usage should remain secondary to Product Items and Physical Store sales.

## Client Portal Claim

Customer-facing voucher claim is available from My WiFi Bag when enabled. Valid vouchers are added as bag items. If the customer already has active time, the voucher item remains available in the bag until manually activated or auto-activation rules apply.

## Not Active

- Wallet / Manual Top-Up.
- RADIUS/WPA2-Enterprise customer login.
- MikroTik HotSpot `login.html` redirect or HotSpot authorization.
- Coinslot/vendo integration.
