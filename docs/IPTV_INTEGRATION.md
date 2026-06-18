# IPTV Integration

3JCentralPisowifi exposes the customer IPTV app through the IPTV web app. XUI admin/provisioning stays private, while customer browser playback can use a dedicated XUI media tunnel when the customer is outside the 3J AP network.

## Topology

- IPTV web app/player: customer local URL `http://192.168.50.15`; internal Next app listener `http://192.168.50.15:3000`
- Private XUI server: `http://10.100.100.100`
- Public XUI playback tunnel: `https://xui.3jhotspot.com`
- Public IPTV hostname: `https://tv.3jhotspot.com`

`tv.3jhotspot.com` is confirmed working. XUI admin/provisioning endpoints must remain private and must not be exposed through MikroTik NAT or customer-facing JavaScript. The public XUI tunnel is only for browser playback/media paths that customer devices must reach outside the 3J AP network.

Customers connected through a 3J AP should normally watch through the local URL `http://192.168.50.15/watch`. This keeps IPTV playback inside the local network and avoids sending local viewers through the public tunnel. Do not send captive clients directly to `:3000`; Omada Pre-Auth Access can allow an IP address, but not an IP plus port, so the IPTV web server must expose port 80 through nginx.

Customers outside the 3J WiFi network should use the public fallback `https://tv.3jhotspot.com/watch`.

The IPTV web server should run a local reverse proxy on port 80:

```text
192.168.50.15:80 -> 127.0.0.1:3000
```

## Cloudflare Public Hostname

Preferred production path:

```text
tv.3jhotspot.com -> Cloudflare Tunnel on IPTV web server -> http://127.0.0.1:3000
```

Keep the hotspot portal tunnel on `net.3jhotspot.com` separate. If the hotspot server tunnel is temporarily used, route only to the IPTV web app service URL, never to XUI.

For outside-network playback, create a separate Cloudflare Tunnel public hostname for XUI media, for example:

```text
xui.3jhotspot.com -> Cloudflare Tunnel on/near the XUI One server -> XUI playback origin
```

The IPTV web app admin portal has two separate tunnel pages under `Settings`:

- `Public HTTPS` manages `tv.3jhotspot.com` on the IPTV web server.
- `XUI HTTPS` manages `xui.3jhotspot.com` by SSHing into the XUI One server, saving encrypted SSH/tunnel secrets, and installing/running `3j-xui-https-cloudflared.service` on the XUI host.

Do not use the old `https://tv1.3jxentro.net/` or `https://tv2.3jxentro.net/` playback server list. XUI playback origins are managed through `XUI HTTPS` / the XUI public browser tunnel URL, not in the IPTV web Secrets page.

The IPTV web app must also normalize stale customer/session `streamBase` values that still contain old `tv*.3jxentro.net` origins into the configured XUI public browser tunnel before calling Xtream/XUI APIs. The production service runs from `.next-runtime`, so deploy source fixes with: stop `3j-tv.service`, run `RUNTIME_SERVICE_NAME=3j-tv.service npm run build:runtime`, then start `3j-tv.service`.

## Admin UI

Use `Admin -> IPTV` to manage:

- IPTV public hostname and public URL
- Internal IPTV web URL
- IPTV web integration secret and watch-token TTL
- Optional IPTV web SSH diagnostics
- XUI playback base URL, public browser tunnel URL/token, server host, optional access code, admin credential/API key, max connections, and disposable player API test line
- Provisioning queue and retry actions

The IPTV page has `Status`, `Provisioning`, `Settings`, and `Logs` tabs. Inside `Settings`, `IPTV Web` contains the public web/token bridge settings and `XUI` contains private XUI settings plus the public XUI playback tunnel URL/token. Secrets are encrypted, masked in the frontend, and never logged in plain text.

The XUI playback base and XUI admin provisioning scheme may differ. In the current deployment, `player_api.php` remains on `http://10.100.100.100`, while the XUI.ONE access-code API is reached by trying the HTTPS scheme variant for the same host.

## Product Items

Product Items can be:

- `WiFi only`
- `IPTV only`
- `WiFi + IPTV`

IPTV-capable products do not choose an XUI package or bouquet. By project decision, newly provisioned XUI lines use the XUI panel default bouquet assignment, which should include all bouquets. XUI lines must be created as non-trial `Never Expire` lines; 3JCentralPisowifi local bag-item time is the access timer.

On the current XUI.ONE install, the access-code `create_line` / `edit_line` endpoint can return `STATUS_SUCCESS` while saving `is_restreamer=1` and `allowed_outputs=[]`. 3JCentralPisowifi must therefore validate line readback. When the limited XUI line-repair DB account is configured, the backend may patch only the just-created line's `is_restreamer` and `allowed_outputs` columns, then validate again before marking IPTV provisioned.

## Provisioning Flow

1. Customer buys an IPTV-capable Product Item.
2. PayMongo payment is verified by webhook or payment status reconciliation.
3. A `customer_bag_items` record is created.
4. IPTV provisioning waits until the customer activates the item.
5. During activation, the system reuses the customer's active provisioned XUI line when IPTV time is still running. If no active IPTV line exists, the system creates a new non-trial, non-restreamer, never-expire `iptv_accounts` XUI line with Access Outputs enabled.
6. My WiFi Bag shows IPTV status.
7. The customer activates the IPTV item manually or through My WiFi Bag auto-activation.
8. The portal displays IPTV entitlement time as its own remaining-time card.
9. When active and provisioned, the customer clicks `Watch IPTV`.
10. The portal creates a short-lived 3J token.
11. If the customer is connected to a 3J AP, the portal redirects to `http://192.168.50.15/watch?threej_token=...`.
12. If the customer is outside the 3J WiFi network, or the local route is unavailable, the system can fall back to `https://tv.3jhotspot.com/watch?threej_token=...`.
13. If the customer taps Watch IPTV from the captive sign-in browser, the portal must not redirect to IPTV. It shows a Chrome reminder instead because the captive browser can block IPTV login/playback.
14. The IPTV web app `/watch` page calls its server route `/api/auth/threej-token`.
15. The IPTV web server resolves the token server-to-server with hotspot API `/api/iptv/session/resolve`.
16. After a successful 3J token resolve, the IPTV web app must not run a blocking XUI precheck in the token handoff route. The token resolve already proves the line is active/provisioned in 3JCentralPisowifi; playback/catalog calls can still report upstream XUI issues later.
17. For local `/watch` requests, the IPTV web app may prefer private XUI routes only when the IPTV web server can connect to the private origin. If the private DNS address times out, keep the configured public XUI tunnel hostname instead of saving a dead private stream base.
16. The IPTV web app logs the customer into the same session model used by the existing IPTV login flow.
17. While the IPTV web session is open, IPTV web polls its `/api/auth/threej-status` route, which calls hotspot API `/api/iptv/session/status`.
18. The status response includes hotspot-controlled expiry UX settings. By default, IPTV web shows a warning toast at 10 minutes remaining and stops playback at 10 seconds remaining.
19. If the pass is expired, deleted, or inside the final stop window, IPTV web clears playback, shows an expired/restricted modal, and returns the customer to the configured portal URL instead of showing the IPTV login page.
20. After local IPTV access is stopped, 3JCentralPisowifi delays the actual XUI line deletion briefly. This gives the player time to stop requesting old stream URLs and reduces the chance that XUI.ONE flood protection blocks the IPTV web server or gateway source IP.

## Safety Boundary

- The hotspot captive portal must never receive or expose raw XUI usernames/passwords.
- The IPTV web app must keep the integration secret server-side.
- The IPTV web app currently reuses its existing browser session format after the trusted token exchange. A later hardening phase can move IPTV playback session state fully server-side.
- `Test XUI API` is read-only. It validates the disposable player API test line and the XUI.ONE access-code API with `get_bouquets`.
- XUI create/sync is performed only during IPTV activation, paid IPTV provisioning jobs created by activation, or explicit admin retry/run actions.
- XUI lines are reusable while the customer still has active IPTV time and never expire at XUI level. A new XUI line is created only when an IPTV item is activated without an active reusable line. When an IPTV item has no remaining active time, is deleted from Customer Devices, or is otherwise removed by an operator, the system immediately stops local access for that item. The cleanup worker deletes the XUI line only after no other active IPTV item references the same account.
- Do not rely on XUI `exp_date` for enforcement. The enforcement chain is `customer_bag_items.active_until` / item status -> IPTV session status API -> IPTV web restriction modal -> XUI line deletion.
- Expiry UX is configured in `Admin -> IPTV -> Settings -> IPTV Web`: `Expiry Warning` defaults to 10 minutes and `Player Stop Window` defaults to 10 seconds. IPTV web should use these values from `/api/iptv/session/status`.
- When access ends, IPTV web should redirect to `https://net.3jhotspot.com/portal` or the configured current portal URL. Do not leave customers on `/login`, `192.168.50.15/login`, or `tv.3jhotspot.com/login`.
- `IPTV only` products activate IPTV entitlement time, but do not activate hotspot internet. `WiFi + IPTV` products still use normal deterministic WiFi authorization and provision IPTV during activation.
- Omada Pre-Auth Access must allow the portal/payment hosts plus the IPTV web hosts (`192.168.50.15` and `tv.3jhotspot.com`). This lets IPTV-only customers open the player without granting general internet access.
- The IPTV web server must be able to reach XUI/player API directly. With a broad RouterOS RAW `notrack` rule, add managed RAW accept exceptions for IPTV web -> XUI, XUI -> IPTV web, and XUI -> the root router's XUI-subnet address used by masquerade. The station push plan also adds scoped NAT from IPTV web to XUI so the XUI server can return traffic reliably.

## XUI Flood Protection Notes

XUI.ONE can block source IPs after repeated failed player/API requests. In this deployment, stale IPTV browser/player retries after a disposable line was deleted caused XUI to add `192.168.50.15` and `10.100.100.1` to its `blocked_ips` table with reason `FLOOD ATTACK`. The `10.100.100.1` source appears when NAT makes XUI see the root router XUI-subnet address instead of the IPTV web server.

If IPTV web can no longer reach XUI while ordinary clients can, check XUI's blocked IP list first. Some XUI builds store an internal whitelist-like setting named `flood_ips_exclude`, but it may not be visible in the GUI. Do not edit the XUI database directly without a backup and a rollback path.

The application-side mitigation is:

- Stop local access immediately by expiring the 3J IPTV token and marking the customer bag item IPTV status deleted.
- Keep the XUI line for a short grace period so the IPTV web page can close/redirect before the browser or player retries old stream URLs.
- Delete the XUI line later through the background cleanup worker.
- Back off delayed-delete retries after failures so the cleanup worker does not hammer XUI.

The IPTV web `/watch` page also has a timeout fallback. If token login cannot complete in time, it shows a server-unreachable message, starts a 10-second return-to-portal countdown, and provides a manual `Return to 3J WiFi Portal` button.

## Database Tables

- `iptv_accounts`: reusable never-expire XUI lines; each line is created by one IPTV bag item, and later active IPTV items can reference the same account while customer IPTV time remains active.
- `iptv_provisioning_jobs`: queued/running/provisioned/failed provisioning jobs.
- `iptv_login_tokens`: short-lived token hashes used by the IPTV web app.
- `customer_bag_items`: stores IPTV status, account reference, account username hint, account expiry, and last watch URL.
