# Client Portal

The client portal is the customer-facing voucher page at:

```text
/portal
```

It can be opened manually for testing, but the production path is Omada captive portal redirect from the open SSID.

## Current Flow

1. Customer connects to the Omada open SSID.
2. Omada redirects the customer browser to `/portal`.
3. The portal captures Omada query parameters when available.
4. Customer enters a voucher code.
5. 3JCentralPisowifi validates the voucher.
6. Omada authorization is attempted for Omada-sourced sessions.
7. After successful authorization, voucher credit is written to wallet/access state.

## What The Browser Can And Cannot Know

The browser cannot reliably detect the device MAC address by itself. Device identity must come from Omada captive portal query parameters or controller/API context.

## Random MAC Handling

After successful voucher redemption, the portal stores a local device-session token. PostgreSQL stores only a hash of that token.

If the phone later changes its private/random WiFi MAC but keeps the same browser token, the backend silently authorizes the new MAC with the remaining time. The voucher is not redeemed again and no extra time is credited.

If the token is lost because browser data or the WiFi profile was cleared, the system cannot safely prove it is the same device.

## Portal Notifications

Portal Notifs can show voucher success, remaining time, expired time, and restored-session messages. Messages support `<TIME>`, `<REMAINING>`, `<VOUCHER>`, `<SSID>`, `<EXPIRES_AT>`, `<BRAND>`, and `<STATUS>`.

Native phone notification-bar behavior depends on the browser and captive portal WebView. When native Web Notifications are blocked or unsupported, the portal shows the notification message inside the page.

## Voucher Redemption

- Valid vouchers are redeemed with source `CLIENT_PORTAL`.
- Used, expired, disabled, and voided vouchers show friendly errors.
- Failed attempts are rate-limited.
- Portal events are logged for troubleshooting.

## Source Of Truth

Vouchers and wallets are stored in PostgreSQL. Omada authorizes network access, but it does not own voucher or wallet state.

## Not Active

- RADIUS/WPA2-Enterprise customer login.
- MikroTik HotSpot `login.html` redirect.
- Payments.
- SMS.
- Coinslot/vendo integration.
