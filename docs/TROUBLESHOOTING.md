# Troubleshooting

Check Docker services:

```bash
docker compose --env-file /opt/3jcentralpisowifi-staging/.env -p centralwifi_staging -f /opt/3jcentralpisowifi-staging/docker-compose.yml -f /opt/3jcentralpisowifi-staging/docker-compose.staging.yml ps
```

Check API health:

```bash
curl http://127.0.0.1:8080/health
```

Check FreeRADIUS logs:

```bash
docker logs centralwifi_staging-radius-1
```

Check PostgreSQL logs:

```bash
docker logs centralwifi_staging-postgres-1
```

Common auth failure reasons:
- User does not exist.
- Wrong password.
- User is disabled.
- Manual balance is empty or expired.
- Same account already has an active session.
- Router/AP uses the wrong shared secret.
- Router/AP points to the wrong production or staging port.

Real FreeRADIUS Packet Test notes:
- The internal Admin Portal packet test is sent by the API container, not by a router/AP.
- It must use the internal Docker client `Docker API Test NAS` and the `RADIUS_DEFAULT_SECRET` configured in FreeRADIUS.
- Do not use a router/AP NAS record shared secret for the internal packet test.
- If the result is `No Reply`, check the RADIUS host, UDP port, Docker networking, firewall, and FreeRADIUS container status.
- If the result is `Wrong Secret`, confirm the internal Docker client secret matches `RADIUS_DEFAULT_SECRET`.
- If the result is `Access-Reject`, use the displayed reason and suggestion in the Admin Portal.

Reject reason mapping:
- `Unknown user`: create the user or verify username spelling.
- `Invalid password`: reset the user password and test again.
- `User disabled`: enable the user account.
- `No active wallet balance`: add manual balance or set unlimited access.
- `Account expired`: extend the valid-until date.
- `Active session already exists`: stop the active session or wait for the active session grace window.
- `Database lookup failed`: check API/PostgreSQL/FreeRADIUS database connectivity.
- `Unknown authorization failure`: check FreeRADIUS logs.

Accounting troubleshooting:
- `No reply from FreeRADIUS`: confirm the target is `radius:1813` for internal UI tests or `SERVER-IP:11813` for staging external tests.
- `Wrong shared secret`: use the internal Docker test client secret for UI tests, or the NAS record secret for real router/AP tests.
- `No matching active session found`: send Accounting Start first or verify username, Calling-Station-ID, and Acct-Session-Id.
- `User not found`: create the user before sending accounting packets.
- `Wallet already empty`: add manual balance or enable unlimited access.
- `Wallet deducted successfully`: confirm the ACCOUNTING DEBIT transaction on the Wallet page.
- `Accounting packet received but ignored`: verify Acct-Status-Type is Start, Interim-Update, or Stop.
- `Database error`: check PostgreSQL health and the FreeRADIUS runtime environment file inside the radius container.

Useful accounting checks:

```bash
docker exec centralwifi_staging-postgres-1 sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT username, acct_status_type, acct_session_id, result, diagnostic_reason, created_at FROM radius_accounting_logs ORDER BY created_at DESC LIMIT 20;"'
```

```bash
docker exec centralwifi_staging-postgres-1 sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT username, acct_session_id, status, last_update_time, stop_time, acct_session_time FROM sessions ORDER BY last_update_time DESC LIMIT 20;"'
```

Firewall checks:

```bash
sudo ufw status
```

Port conflict checks:

```bash
sudo ss -tulpn | grep -E ':(80|8080|1812|1813|11812|11813)'
```

## Omada Controller Troubleshooting

Omada server not reachable:
- Confirm `192.168.50.71` is powered on and on the same network.
- From the Omada Controller page, run Test Web UI Reachability.
- Check `8088/tcp` and `8043/tcp`.

SSH failed:
- Confirm SSH is enabled on `192.168.50.71`.
- Confirm username, password or private key, and port `22`.
- Saved secrets are masked and never displayed after saving.

Docker not installed on Omada server:
- The Phase 1D install action attempts to install Docker and the Compose plugin through controlled SSH commands.
- If install fails, view the Omada install logs in the Admin Portal.

Omada UI not reachable:
- Confirm the install status is Running.
- Check ports `8088/tcp` and `8043/tcp`.
- If using bridge mode, confirm the container ports are mapped.
- If AP discovery/adoption is unreliable, host mode may be easier on local networks.

AP cannot adopt:
- Confirm required ports `29810/udp`, `29811/tcp`, `29812/tcp`, `29813/tcp`, and `29814/tcp`.
- Confirm the AP can reach `192.168.50.71`.
- Confirm the Omada server firewall allows those ports.

RADIUS no reply from Omada:
- Confirm Omada points to RADIUS server `192.168.50.70`.
- Use staging ports `11812/11813` or production ports `1812/1813`.
- Confirm the NAS client shared secret matches the Omada RADIUS profile.
- Check FreeRADIUS logs with `docker logs centralwifi_staging-radius-1`.

Wrong NAS source IP:
- FreeRADIUS trusts the source IP of the RADIUS packet.
- Add the Omada Controller IP or AP IP as a NAS client, depending on what FreeRADIUS logs show.

Accounting not sent by AP:
- Enable accounting in the Omada RADIUS profile if available.
- Set the accounting port.
- Set interim update to 300 seconds if available.
- Confirm Accounting Start/Interim/Stop appear on the Sessions page.

## Phase 1E Omada API Automation Troubleshooting

Omada API login failed:
- Check username and password.
- Check `https://192.168.50.71:8043` is reachable.
- Disable TLS verification for lab/self-signed certificates.
- Confirm Omada first-time setup is complete.

No Omada sites detected:
- Log into Omada manually and verify a site exists.
- Confirm the account has permission to view sites.
- Use the Manual Fallback Instructions panel if the Omada API version uses different endpoints.

RADIUS profile automation failed:
- Confirm Omada API login works.
- Confirm an Omada site is selected.
- Use the fallback values to create the profile manually in Omada.

SSID creation failed:
- Confirm the RADIUS profile exists in Omada.
- Create SSID `3J-Test-WiFi` manually with WPA2-Enterprise and the staging RADIUS profile.
- Do not enable captive portal, vouchers, guest network, or VLAN for Phase 1E.

Unknown RADIUS client from Omada/AP:
- Check FreeRADIUS logs for the source IP.
- Add that IP as a NAS / Router / AP Client in 3JCentralPisowifi.
- Use the same shared secret configured in Omada.

Wrong shared secret:
- The Omada RADIUS profile secret and the 3JCentralPisowifi NAS client secret must match exactly.

Accounting not arriving:
- Enable accounting in the Omada RADIUS profile.
- Use staging accounting port `11813`.
- Confirm the AP sends accounting packets.
- Check FreeRADIUS logs and the Sessions page.

## Captive Portal Priority Notes

The main customer access direction is now open SSID + Captive Portal + Voucher. WPA2-Enterprise and Omada RADIUS profile automation are advanced/lab tools.

If an operator expects customers to enter a WPA2 username/password:
- Re-check the current project direction.
- Customers should connect to an open SSID and enter a voucher on the portal once the captive portal phase is built.

If the Captive Portal page says features are not built yet:
- This is expected after the UI cleanup.
- Voucher Management is the next development phase.
- Do not remove or rewrite working Phase 1C RADIUS/accounting foundations; they remain useful for backend session and accounting behavior.

## Voucher Management Troubleshooting

Voucher not found:
- Check the code for typos.
- Voucher comparison is case-insensitive and ignores spaces/hyphens, but the code must exist in the database.

Voucher already used:
- Single-use vouchers cannot be redeemed again after status becomes `USED`.
- Create a new voucher or use a voucher with remaining redemption count.

Voucher expired:
- Check the voucher `expires_at`.
- Expired vouchers cannot be redeemed.

Voucher disabled:
- An admin disabled the voucher.
- Re-enable it from Vouchers -> Voucher List if it should be usable.

Voucher voided:
- Voided vouchers are intentionally invalidated.
- Create a new voucher instead of reusing a voided one.

User not found during test redeem:
- Select an existing customer/account on the Test Redeem tab.
- Confirm the user has not been deleted.

## Client Portal Troubleshooting

Portal page not loading:
- Open `http://192.168.50.70:8080/portal` for staging.
- Confirm the proxy container is running.
- Confirm `/api/portal/settings` returns JSON.

Voucher not found:
- Re-enter the code exactly as printed.
- Spaces and hyphens are ignored, but the code must exist.

Voucher already used:
- Single-use vouchers cannot be reused.
- Ask the operator for a new voucher.

Voucher expired:
- The voucher expiry date has passed.
- Use a new voucher.

Rate limited:
- Too many failed attempts were made from the same IP/session.
- Wait a few minutes and try again.

Portal redeemed but internet is not enabled:
- This is expected in Phase 2B.
- Voucher redemption and wallet crediting work, but captive portal redirect/enforcement is a future phase.

## Phase 2C Omada Captive Portal Troubleshooting

Omada API login failed:
- Check Omada username/password under Omada Controller -> Advanced/API settings.
- Confirm Omada first-time setup is complete.
- Disable TLS verification for lab self-signed certificates.

Omada site not selected:
- Use Omada Controller -> Advanced to refresh sites and save one selected site.
- Captive Portal Omada actions need a selected site.

Open SSID creation failed:
- Use the Manual Setup Guide in Admin -> Captive Portal.
- Create the SSID configured in APs Deployment -> Sites -> Configurations manually as an Open SSID on one test AP.
- Captive Portal reads the SSID from APs Deployment and does not keep a separate editable SSID value.

External portal configuration failed:
- Omada controller API paths vary by version.
- Configure External Portal manually and point it to `http://192.168.50.70:8080/portal`.

Missing client MAC/token from Omada redirect:
- Confirm Omada is redirecting to the portal with client parameters.
- Test with a phone connected through the Omada SSID, not by directly opening the portal URL.

Voucher valid but Omada authorization failed:
- Check Captive Portal -> Authorization Logs.
- The voucher should remain unused when authorization fails.
- Use manual Omada setup if this controller version rejects API authorization.

Walled garden may be missing portal server:
- Add `192.168.50.70` and the portal URL to pre-auth/walled garden access.
- Allow DNS if needed by the Omada portal flow.

Client did not redirect to portal:
- Confirm captive portal is enabled on the SSID configured in APs Deployment -> Sites -> Configurations.
- Confirm the SSID is applied to the test AP.
- Disconnect/reconnect the phone to WiFi and clear captive portal browser state.

Client authorized but no internet:
- Check Omada portal policy after authorization.
- Check upstream gateway/DNS outside 3JCentralPisowifi.
- Confirm only one test AP is being used before wider rollout.

## MikroTik Captive Portal Setup Troubleshooting

MikroTik API test failed:
- Confirm RouterOS API service is enabled.
- Use port `8728` for plain API or `8729` for TLS API.
- Confirm firewall rules allow the 3JCentralPisowifi server to reach the MikroTik API port.
- Confirm the API username/password are correct.

MikroTik API account requirement:
- Use a dedicated full/write RouterOS API account for captive portal automation.
- The account needs write access for HotSpot, walled garden, client authorization, and portal enforcement.
- Do not use the main MikroTik admin account.

Portal design changed but voucher form disappeared:
- Open `/admin/captive-portal/editor`.
- Make sure the HTML template contains `{{voucher_form}}`.

## MikroTik Preflight Scanner Troubleshooting

Preflight scan failed:
- Confirm the MikroTik router is reachable from the 3JCentralPisowifi server.
- Confirm RouterOS API service is enabled.
- Use port `8728` for plain API or `8729` for API-SSL.
- Check MikroTik firewall rules for the API port.
- Check the saved dedicated API username/password.

Failed due to invalid RouterOS text:
- MT-2.1 sanitizes RouterOS null bytes and control characters before database storage.
- Re-run Prescan All Routers.
- If the same router still fails, check `Network -> MikroTik -> Configuration`, then use the router row's scan status or `View Scan Result`. The failure should now be a clean readable message instead of a PostgreSQL unicode escape error.

Unexpected unsupported path warnings:
- RouterOS versions differ.
- Unsupported paths are recorded as warnings and should not block the whole scan.
- Review the unsupported path list only if an expected feature is missing from the scan.

VLAN conflict:
- The customer VLAN ID entered for captive portal setup already exists on the router.
- Choose a different VLAN or confirm manually that the existing VLAN is intended for captive portal clients.

Subnet or pool conflict:
- The proposed client subnet or DHCP pool overlaps existing router configuration.
- Use a dedicated non-overlapping client network and pool.

High-risk/core router warning:
- Public IP, OSPF, many routes, PPPoE, or WireGuard indicators may mean this router is sensitive.
- Do not continue with captive portal setup until the operator confirms the router role.

PPPoE router shown as requires confirmation:
- This is expected. PPPoE access concentrators are not automatically read-only/core anymore.
- Use HotSpot Gateway only if captive portal users will be isolated on a new dedicated VLAN/subnet/interface and PPPoE objects will not be touched.

CRS/switch shown as VLAN trunk helper:
- This is expected. CRS/switch devices should carry VLANs, not host HotSpot/DHCP/NAT.

AI explanation unavailable:
- This is expected. AI Explain was removed from the active workflow.
- Use `Network -> MikroTik -> Configuration -> View Scan Result` to inspect findings, conflicts, role guess, and existing router data instead.

## MikroTik Safe Deployment Mode Troubleshooting

Prescan All Routers shows partial success:
- This is expected when one router is offline or credentials are wrong.
- Open Network -> MikroTik -> Configuration and check the failed router row.
- Fix API reachability or credentials, then run that router's scan again.

Add Station is disabled:
- Run `Prescan All Routers` or `Run Scan` from at least one router row in Network -> MikroTik -> Configuration.
- Add Station stays disabled until read-only scan data exists.
- If a router was scanned but the button is still disabled, refresh the Configuration tab and confirm the latest preflight status is visible in the table.

AP Management Details is disabled:
- Run at least one read-only preflight scan first. Central AP management uses scan data to validate selected bridges, tagged ports, existing VLANs, subnets, and pools.

AP management save is blocked:
- Confirm the AP management VLAN is not already used by a station customer VLAN.
- Confirm the AP management subnet does not overlap station customer subnets or existing root-router subnets.
- Select only detected non-PPPoE bridges/interfaces and tagged ports.

AP management push stops:
- The push modal sends one RouterOS command at a time and stops on the first error.
- Reopen `Push AP Management Config`; the system rechecks already-pushed objects and marks detected steps as already existing.

Router appears read-only/core:
- Do not select HotSpot Gateway unless a network expert confirms a dedicated non-conflicting captive portal VLAN/network can be used.
- Prefer Read-only/Core for ISP core routers and use a different pilot gateway.

Expert override is required:
- Expert override only records risk acceptance.
- It does not apply MikroTik configuration.
- It does not bypass VLAN/subnet/pool conflicts or missing required fields.
- Expert override is not part of the current active Configuration UI.

## Manual MikroTik Configuration Troubleshooting

Manual setup field validation fails:
- Open Network -> MikroTik -> Configuration and run Prescan All Routers or scan the router row first.
- Use View Scan Result to inspect existing VLAN/subnet/pool data, then fill the station modal fields.
- Fix every field-level warning before applying a RouterOS step.

Invalid client network:
- Use IPv4 CIDR notation such as `10.15.0.0/19`.
- Avoid very small networks. The system expects at least a practical DHCP pool size.
- Make sure gateway IP and DHCP pool are inside the CIDR, and that the DHCP pool does not include the gateway.

Customer VLAN is blocked:
- The proposed customer VLAN already exists on the selected MikroTik or conflicts with policy.
- Choose an unused customer VLAN for the selected MikroTik, then validate again.
- Do not reuse management, PPPoE, core, or transport VLANs for captive portal customers.

Wrong VLAN parent interface:
- The VLAN parent interface must be the bridge or trunk carrying the customer VLAN toward CRS/OLT/AP devices.
- Do not use a physical interface just because it exists in the scan. Confirm the actual path first.

MT-4 readiness is blocked by VLAN path:
- Fill in the Gateway VLAN Parent Interface / Bridge.
- Describe whether CRS, OLTs, switches, or direct AP uplinks are involved.
- Set AP receives VLAN as tagged, untagged, or unknown.
- If AP receives tagged VLAN, make the open SSID use the customer VLAN ID from the planning questions.
- Set the VLAN Path Planner confirmation status to `CONFIRMED` only after the path has been reviewed.

Large client subnet warning:
- A subnet larger than `/22`, such as `/19`, is allowed only with a warning.
- For the first pilot, prefer `/24` or `/22` unless the network design really needs a larger client pool.
