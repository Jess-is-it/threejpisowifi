# Client Portal

The client portal is the customer-facing voucher page at:

```text
/portal
```

It can be opened manually for testing, but the production path is Omada captive portal redirect from the open SSID.

## Current Flow

1. Customer connects to the Omada open SSID.
2. Omada redirects the customer browser to `/portal`.
3. The portal opens on the No Internet page with operator-managed avatar/headline.
4. Customer can buy a Product Item, enter a voucher, or save a verified profile.
5. Successful Product Item payments are saved as individual customer bag items.
6. 3JCentralPisowifi validates payment/voucher/gift access.
7. Omada authorization is attempted only for supported Omada-sourced sessions.
8. The customer bag, voucher records, and portal session remain the source of truth for remaining access.

## What The Browser Can And Cannot Know

The browser cannot reliably detect the device MAC address by itself. Device identity must come from Omada captive portal query parameters or controller/API context.

## Random MAC Handling

After successful voucher redemption, the portal stores a local device-session token. PostgreSQL stores only a hash of that token.

If the phone later changes its private/random WiFi MAC but keeps the same browser token, the backend silently authorizes the new MAC with the remaining time. The voucher is not redeemed again and no extra time is credited.

If the token is lost because browser data or the WiFi profile was cleared, the system cannot safely prove it is the same device.

Verified customer profiles add a second recovery path. The customer can use Report Missing Time from the portal Help button, verify the same contact number by A2P code, and move active remaining time to the current portal device/session.

## Customer Profile And Welcome Gift

- Profile save requires name, unique verified contact number, optional email, terms/data consent, and optional marketing SMS consent.
- Contact verification sends a 4-character code through Smart A2P. Provider credentials are configured in System Settings -> A2P Messaging, while the portal-specific Sender ID and local confirmation-SMS credit tracking are configured in Captive Portal -> Message Defaults.
- A verified profile creates a one-time FREE 1D welcome gift voucher but does not activate it automatically.
- The welcome gift remains visible below the avatar until the customer unwraps and redeems it.
- Contact number uniqueness prevents repeated welcome gifts and supports missing-time recovery.

## Customer Bag

- Paid Product Items are stored as separate bag items instead of being merged into one timer.
- The portal shows My WiFi Bag with the active package, queued packages, and consumption history.
- Customers can drag queued items to choose which package activates next.
- Auto Activate can be enabled per customer. When enabled, the next queued item starts 10 seconds before the current item ends for a smoother transition.
- Bag history records whether Auto Activate was enabled when an item was consumed.
- Buying while outside a 3J AP saves the package to the bag. It does not grant internet until the customer connects through the supported captive portal path.

## Message Admin

The Help button includes Message Admin. This is an in-system support inbox, not SMS. Customers can send messages from the portal, and operators reply from Admin -> Support Inbox.

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
- Coinslot/vendo integration.
