# Captive Portal Integration

The active customer access flow is Omada Captive Portal + Voucher. MikroTik is retained for station transport only.

## Active Flow

1. Customer connects to the open SSID configured in `APs Deployment -> Sites -> Configurations`.
2. Omada captive portal redirects the customer to `/portal`.
3. `/portal` captures Omada client parameters.
4. Customer enters a voucher.
5. 3JCentralPisowifi validates the voucher from PostgreSQL.
6. If the session came from Omada, 3JCentralPisowifi attempts Omada client authorization.
7. After successful authorization, the voucher is consumed and wallet/access state is credited.

## Component Roles

Omada:
- AP adoption.
- SSID/radio/VLAN settings.
- Captive portal redirect/enforcement.
- Client authorization after voucher success.

MikroTik:
- Station VLAN transport.
- DHCP/NAT/routing for customer and AP management networks.
- Read-only preflight scanning to avoid VLAN/subnet/pool conflicts.
- No active MikroTik HotSpot enforcement.

3JCentralPisowifi:
- Voucher validation.
- Wallet/source-of-truth access state.
- Portal sessions/events.
- Omada authorization logs.
- Station planning and reviewed MikroTik transport push.

## Portal URLs

```text
Local/Staging fallback: http://192.168.50.70:8080/portal
Production HTTPS:       https://portal.3jhotspot.com/portal
```

For production, configure the public HTTPS endpoint in `System Settings -> Public HTTPS`. The preferred path is Cloudflare Tunnel to `http://proxy:80`, avoiding MikroTik inbound port-forwarding.

## Omada Query Parameters

The portal accepts common Omada-style parameters:

```text
clientMac
client_mac
apMac
ap_mac
gatewayMac
gateway_mac
vid
site
ssid
redirectUrl
redirect_url
t
token
authToken
```

Raw query parameters are stored with `portal_sessions` for diagnostics.

## Voucher Behavior

Manual `/portal` testing can redeem a voucher into wallet/access state without gateway authorization.

Omada-sourced sessions validate the voucher first, then attempt Omada authorization. If Omada authorization fails, the voucher is not consumed.

Unlimited vouchers without an expiry use the configured default authorization duration for Omada authorization.

## Random MAC / Private WiFi Address

3JCentralPisowifi handles normal phone private-MAC changes with a device-session token.

- After voucher success, the portal stores a secure token in the browser.
- The database stores only the token hash.
- If the same token returns with a new client MAC and remaining time still exists, the backend silently authorizes the new MAC for the remaining time.
- The voucher is not consumed again and no extra time is credited.
- Rebinds are limited and logged for operator review.

This avoids Google login and avoids unreliable fingerprinting. If the browser token is lost, the system cannot safely prove that the new MAC belongs to the same phone.

## Portal Notifications

Admin -> Captive Portal -> Portal Notifs controls optional customer messages for voucher success, remaining-time warning, time consumed, and restored sessions.

Supported template tags are `<TIME>`, `<REMAINING>`, `<VOUCHER>`, `<SSID>`, `<EXPIRES_AT>`, `<BRAND>`, and `<STATUS>`.

The portal attempts browser/Web Notifications when the mobile browser supports them. Captive portal mini-browsers and plain HTTP portals often block native notification prompts, so the same message is always shown inside the portal as a fallback. The OS-level WiFi sign-in notification text is controlled by Android/iOS and cannot be customized by 3JCentralPisowifi.

## MikroTik Station Transport

Network -> MikroTik is still active for station transport:

- Add Router stores RouterOS API access.
- Overview runs read-only preflight scans.
- Configuration creates station router chains.
- AP Management creates a central AP management VLAN/subnet plan.
- Station Push Config applies only reviewed VLAN/DHCP/NAT/trunk transport steps.
- Station Push Config also applies station-scoped one-device voucher fairness rules on the root gateway so normal phone hotspot sharing is blocked.

Station Push Config does not create MikroTik HotSpot profile/server, walled-garden, forced DNS redirect, or managed `login.html`.

## One-Device Voucher Fairness

Omada authorizes the device that redeemed the voucher, but it cannot reliably see another phone hidden behind that device's personal hotspot/NAT. 3JCentralPisowifi therefore enforces voucher fairness on the MikroTik station root gateway.

The managed station rules:

- Clamp return traffic to the customer VLAN with `TTL=1`.
- Drop common tethered source TTL values `63` and `127`.
- Insert station-scoped established/related accept rules before active FastTrack rules when needed so TTL enforcement is not bypassed.
- Are scoped to the station client subnet/VLAN interface.
- Are removed by Station Remove Config using exact managed comments.

This blocks normal hotspot sharing from phones. It is not a cryptographic guarantee against rooted/custom clients that deliberately manipulate TTL.

Office AP Path is retired from the active UI. The current AP adoption process is to connect the AP directly to the office subnet, adopt it in Omada, then set the AP management VLAN after adoption before moving it to the station path.

## Manual Omada Setup

1. Open `https://192.168.50.71:8043`.
2. Adopt the AP into the correct Omada site.
3. Create or edit the open SSID from APs Deployment configuration.
4. Enable Portal Authentication / External Portal.
5. Set the external portal URL to `http://192.168.50.70:8080/portal`.
6. Configure the SSID VLAN to the station customer VLAN.
7. Add pre-auth access for `192.168.50.70` and DNS if needed.
8. Apply to one AP first.
9. Connect a phone and redeem one test voucher.

## Troubleshooting

Client does not redirect:
- Confirm Omada Portal Authentication is enabled on the open SSID.
- Confirm the AP is connected in the selected Omada site.
- Confirm the SSID is broadcasting and uses the station customer VLAN.
- Confirm walled garden/pre-auth access allows the portal server.

Voucher valid but authorization failed:
- Check Captive Portal -> Authorization Logs.
- Confirm Omada sends client context to `/portal`.
- If Omada API authorization is unsupported, authorize/test manually from Omada and record the limitation.

Client authorized but no internet:
- Confirm MikroTik station transport has DHCP/NAT/routing pushed.
- Confirm the phone received an IP from the station customer subnet.
- Confirm the SSID VLAN matches the station VLAN.

PayMongo GCash checkout:
- Product Items shown in the captive portal can start a PayMongo hosted checkout when System Settings -> Payments is enabled and the active Test/Live mode has keys saved.
- A PayMongo redirect back to `/portal` is only a status hint. 3JCentralPisowifi grants access only after the backend confirms the checkout is paid, either from `/api/payments/paymongo/webhook` with a valid `Paymongo-Signature` or from a server-side PayMongo order reconciliation check.
- Successful webhook fulfillment creates a system voucher for the Product Item duration and then uses the same Omada authorization path as normal voucher redemption.
- Valid signed PayMongo webhooks are acknowledged with HTTP 200 after being recorded. If local fulfillment fails, the event is marked failed for operator review rather than returning HTTP 500 to PayMongo.
- If the webhook secret is not configured, customers can reach PayMongo checkout but access remains pending after payment until the webhook is configured and delivered.

## Retired From Active Workflow

- RADIUS / FreeRADIUS customer login.
- NAS/RADIUS client management.
- WPA2-Enterprise test SSID automation.
- AI/OpenAI assistant planning.
- MikroTik HotSpot enforcement and managed `login.html`.
- SMS, coinslot/vendo, WireGuard automation, and production rollout automation.
