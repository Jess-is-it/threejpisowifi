# Client Portal

Phase 2B adds the customer-facing voucher redemption page.
Phase 2C adds Omada captive portal context capture and authorization attempts.

## What It Is

The client portal is the page customers will use after connecting to the open WiFi SSID. For now it can be opened manually:

```text
http://192.168.50.70:8080/portal
```

Later, MikroTik HotSpot should redirect customers to this page automatically. Omada can still be used for AP/SSID management.

## What Works Now

- `/portal` loads without admin login.
- Customers can enter a voucher code.
- Valid vouchers are redeemed with source `CLIENT_PORTAL`.
- Voucher redemption credits the wallet/access of an internal portal customer account.
- Portal sessions store browser/session context.
- Portal sessions store Omada query parameters when Omada redirects a client.
- Portal events log portal views, submissions, success, failure, and status checks.
- Basic portal branding can be edited from Admin -> Captive Portal.
- Portal HTML/CSS can be edited at `/admin/captive-portal/editor`.
- Omada-sourced sessions can attempt Omada client authorization after voucher validation.
- MikroTik router connection records can be stored and tested from Admin -> Network -> MikroTik.

## What Is Not Built Yet

- Production WiFi rollout.
- Full MikroTik HotSpot enforcement/authorization automation.
- WireGuard tunnel automation.
- Payments, SMS, coinslot, or vendo integration.

## Future Redirect Parameters

The portal captures these optional query parameters:

```text
client_mac
clientMac
client_ip
ap_mac
apMac
gatewayMac
gateway_mac
vid
ssid
site
gateway
redirect_url
redirectUrl
nas_id
session_id
token
authToken
```

Example:

```text
/portal?client_mac=AA:BB:CC:DD:EE:FF&client_ip=10.0.0.25&ssid=YOUR-SITE-SSID&site=Centro
```

Browsers cannot reliably detect a device MAC address by themselves. Device identifiers will later come from MikroTik or Omada redirect parameters.

If Omada parameters are present, the portal session source is `OMADA`. A valid voucher is checked first, Omada authorization is attempted, and the voucher is consumed only after authorization succeeds. If authorization fails, the voucher remains usable and the customer is told to ask the operator.

## Manual Test Steps

1. Create a time-based voucher in Admin -> Vouchers.
2. Open `/portal` in a browser or phone.
3. Enter the voucher code.
4. Confirm success message and time remaining.
5. Check Admin -> Captive Portal for portal events.
6. Check Admin -> Vouchers -> Redemption Logs for source `CLIENT_PORTAL`.

## Omada Test Steps

1. Configure one test AP and the open SSID from APs Deployment -> Sites -> Configurations -> SSID and Security.
2. Set the Omada external portal URL to `/portal`.
3. Connect a phone and confirm the portal opens with Omada query parameters.
4. Redeem a test voucher.
5. Check Admin -> Captive Portal -> Portal Sessions.
6. Check Admin -> Captive Portal -> Authorization Logs.

## Source Of Truth

Vouchers credit wallets. After redemption, wallet and session records remain the access source of truth.
