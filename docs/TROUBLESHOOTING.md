# Troubleshooting

Check Docker services:

```bash
docker compose --env-file /opt/3jcentralpisowifi-staging/.env -p centralwifi_staging -f /opt/3jcentralpisowifi-staging/docker-compose.yml -f /opt/3jcentralpisowifi-staging/docker-compose.staging.yml ps
```

Check API health:

```bash
curl http://127.0.0.1:8080/health
```

Check PostgreSQL logs:

```bash
docker logs centralwifi_staging-postgres-1
```

Current access troubleshooting:
- The active customer flow is Omada open SSID captive portal -> `/portal` voucher entry -> Omada client authorization.
- RADIUS packet tests, NAS client management, and old accounting sessions are removed from the active UI/API.
- If a removed endpoint returns `410 Gone`, use Captive Portal sessions, Authorization Logs, Omada Controller, APs Deployment, or Network -> MikroTik instead.
- Wallet remains active and should be checked when voucher credit or future balance behavior is suspected.

Firewall checks:

```bash
sudo ufw status
```

Port conflict checks:

```bash
sudo ss -tulpn | grep -E ':(80|8080|8043|8088)'
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
- Confirm required ports `29810/udp`, `29811/tcp`, `29812/tcp`, `29813/tcp`, `29814/tcp`, and newer controller management ports `29815/tcp`, `29816/tcp`, `29817/tcp` when used by your Omada version.
- Confirm the AP can reach `192.168.50.71`.
- Confirm the Omada server firewall allows those ports.

Captive portal authorization failed:
- Check Admin -> Captive Portal -> Authorization Logs.
- Confirm Omada sent client MAC/site/session parameters to `/portal`.
- Confirm the Omada API account can authorize captive portal clients.
- If API authorization is unsupported for this Omada version, use the manual Omada portal flow and keep the failure visible in Authorization Logs.

## Omada API Automation Troubleshooting

Omada API login failed:
- Check username and password.
- Check `https://192.168.50.71:8043` is reachable.
- Disable TLS verification for lab/self-signed certificates.
- Confirm Omada first-time setup is complete.

No Omada sites detected:
- Log into Omada manually and verify a site exists.
- Confirm the account has permission to view sites.
- Use the Manual Fallback Instructions panel if the Omada API version uses different endpoints.

SSID creation failed:
- Confirm the AP is adopted in Omada and in the correct site.
- Confirm Sites -> Configurations has the desired SSID/security/VLAN.
- Use List of APs -> Push WiFi Config manually. The system no longer auto-applies SSID changes.
- If Omada rejects the update endpoint, configure the SSID manually in Omada and keep the error visible in the AP details panel.

## Captive Portal Priority Notes

The main customer access direction is open SSID + Omada Captive Portal + Voucher. WPA2-Enterprise and Omada RADIUS profile automation are retired from the active system.

If an operator expects customers to enter a WPA2 username/password:
- Re-check the current project direction.
- Customers should connect to an open SSID and enter a voucher on the portal.

If the Captive Portal page shows authorization failures:
- Confirm the phone was redirected by Omada, not by MikroTik HotSpot.
- Confirm `/portal` captured Omada query parameters.
- Confirm voucher redemption did not consume the voucher when Omada authorization failed.

## Portal Notifications Do Not Show In Phone Notification Bar

- Confirm Admin -> Captive Portal -> Portal Notifs is enabled.
- Confirm the specific success/remaining/expired/restored notification switch is enabled.
- Browser/Web Notifications usually require a secure context. Plain HTTP captive portal pages and captive portal mini-browsers may block native notification prompts.
- The portal still shows the configured message inside the page as fallback.
- Android/iOS controls the built-in `Sign in to WiFi network` notification text; 3JCentralPisowifi cannot customize that OS notification.

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
- If the same phone changed its private/random WiFi MAC, the portal should reconnect automatically only when the browser still has the 3J device-session token.
- If browser storage was cleared or the WiFi profile was forgotten, the system cannot safely prove it is the same phone.

Phone changed MAC and lost access:
- Reopen the captive portal from the same browser/captive popup if possible.
- Check Admin -> Captive Portal -> Sessions and Authorization Logs for `MAC_REBIND_*` events.
- Check `portal_mac_rebind_events` if operator-level detail is needed.
- If the rebind limit was reached, issue a new voucher or handle the customer manually.

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

Voucher works on one phone, then another phone gets internet through that phone's hotspot:
- Re-open Network -> MikroTik -> Configuration and click Push Config for the affected station.
- The station plan should include `Enable one-device voucher TTL guard`, `Block likely phone hotspot sharing traffic`, and `Block likely Windows-over-phone hotspot sharing traffic`.
- If the root gateway has FastTrack enabled, the plan should also include station-scoped FastTrack bypass steps so the TTL guard is not skipped for established traffic.
- These rules live on the station root gateway and are managed by exact `3J Station - ... VLAN {id}` comments.
- After pushing, test again by redeeming a voucher on Phone A, enabling Phone A hotspot, and connecting Phone B to it. Normal tethered traffic should fail while Phone A remains online.
- This is a practical fairness control for normal phones. A rooted/custom client may still attempt TTL manipulation, so investigate repeat abuse from the MikroTik rule counters and portal/session logs.

## MikroTik Transport Setup Troubleshooting

MikroTik API test failed:
- Confirm RouterOS API service is enabled.
- Use port `8728` for plain API or `8729` for TLS API.
- Confirm firewall rules allow the 3JCentralPisowifi server to reach the MikroTik API port.
- Confirm the API username/password are correct.

MikroTik API account requirement:
- Use a dedicated full/write RouterOS API account for station transport automation.
- The account needs write access for station VLAN, DHCP, NAT, interface-list, and AP-management transport objects.
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
- Use station transport only on a dedicated VLAN/subnet/interface and do not touch PPPoE objects.

CRS/switch shown as VLAN trunk helper:
- This is expected. CRS/switch devices should carry VLANs. They should not own the customer gateway/DHCP/NAT role unless they are intentionally designed as the root station router.

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
- Do not push station transport changes to a core router unless a network expert confirms the exact dedicated VLAN/network path.
- Prefer a non-core station gateway for first rollout.

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

## OCP-2 Omada Station Portal Troubleshooting

Omada Portal readiness is blocked:
- Open Network -> MikroTik -> Configuration and click `Omada Portal` on the station.
- Fix any item marked `BLOCKED` or `NEEDS_ACTION`.
- The most common blocker is selected Omada site VLAN not matching the MikroTik station VLAN.

Selected Omada site VLAN does not match station VLAN:
- Go to APs Deployment -> Sites -> Configurations.
- Set that Omada site's VLAN tag to the same customer VLAN shown in the station plan.
- Reopen the station `Omada Portal` modal and refresh readiness.

Omada API action fails:
- The Omada Controller version may not support the endpoint attempted by the adapter.
- Use the manual checklist in the station Omada Portal modal.
- Configure the open SSID, external portal URL, and pre-auth/walled-garden entries directly in Omada Controller.

Phone connects but does not redirect:
- Confirm the AP is using the Omada SSID tied to the station VLAN.
- Confirm Omada captive portal is enabled on that SSID/site.
- Confirm pre-auth access allows `192.168.50.70` and `192.168.50.70:8080`.
- Confirm the phone receives an IP from the MikroTik station client subnet.
- Confirm MikroTik is not source-NATing station clients when they reach Omada/portal servers. The station root gateway must have a `srcnat accept` no-NAT rule from the station subnet to the office portal subnet before the station masquerade rule.
- Confirm the station internet NAT is WAN-only. A broad `srcnat masquerade src-address=<station subnet>` can hide the real phone IP from Omada and break captive portal session matching.
- Expected managed rules use comments `3J Station - preserve client IP for VLAN {vlan_id} to portal office subnet` and `3J Station - NAT for VLAN {vlan_id} clients`.

Voucher works manually but Omada does not authorize:
- Check Captive Portal -> Authorization Logs.
- Confirm Omada redirect includes client parameters such as MAC/token/site.
- Run `Verify Captive Portal Setup` from the station Omada Portal modal.

Omada Portal says station site is not bound:
- Open the station `Omada Portal` modal.
- Select the Omada site that owns that station's APs.
- Click `Save Binding`, then refresh readiness.

Station Omada VLAN check is blocked:
- The Omada/local site VLAN tag does not match the MikroTik station customer VLAN.
- Update the site VLAN in APs Deployment -> Sites -> Configurations or edit the station customer VLAN if the station design is wrong.
- Do not test the open SSID until Omada SSID VLAN and station customer VLAN match.

Omada automation updates the wrong site:
- Confirm the station has its own Omada site binding.
- Reopen the `Omada Portal` modal and check the Omada Site card before running Create/Update Open SSID or Configure External Portal.
- The station-bound site should be used for station automation; the global selected site is only a fallback/reference.

Station Omada action button is disabled:
- Open the station `Omada Portal` modal and check the disabled reason under Omada automation actions.
- Common causes are missing Omada API credentials, no station-bound Omada site, or no Portal URL.
- Save the Station Omada Site binding first, then refresh the modal.

Station Omada action history shows failure:
- Read the latest message in the station `Recent Omada action history`.
- Omada Controller versions expose different API paths. If Create/Update Open SSID or Configure External Portal fails, use the manual checklist in the same modal.
- Verify the existing Omada SSID VLAN manually if the action says the SSID already exists.

Created Omada SSID has the wrong VLAN:
- The station customer VLAN should match the Omada site/SSID VLAN.
- Create/Update Open SSID now sends the station VLAN to Omada for new SSID creation, but existing SSID update behavior depends on Omada Controller version.
- Open Omada Controller and verify the SSID VLAN before testing phones.

List of APs shows `CONFIGURING`, but no one clicked Push WiFi Config:
- List of APs now uses cached PostgreSQL AP rows only. Opening the page and pressing Refresh do not contact Omada Controller.
- A `CONFIGURING` status can be an old cached Omada status from a previous sync/push/test.
- Adopt or inspect the AP directly in Omada Controller. When ready, click `Push WiFi Config` in List of APs; that action is the only AP list workflow that refreshes Omada and pushes SSID/VLAN settings.
- If the cached AP row is no longer relevant, delete it from List of APs. This removes the local row only and does not delete/forget the AP in Omada.

AP has `10.111.x.x` but does not appear in Omada:
- Push or re-check Network -> MikroTik -> AP Management after saving the Omada API controller host.
- The AP management DHCP network should advertise DHCP option 138 with the Omada Controller IP, for example `3J-OMADA-CONTROLLER-V111 = 192.168.50.71`.
- AP Management Push Config should also show MikroTik forward allow rules from the AP management subnet to the Omada Controller for `29810/udp` and `29811-29817/tcp`. Re-open Push Config after an Omada v6 update so the new `29817/tcp` rule is detected or added.
- Renew the AP DHCP lease or reboot the AP after the option is pushed.
- Confirm the Omada server can route back to `10.111.0.0/24`. If its default gateway is not the CCR/MikroTik, add a return route to the AP management subnet via the CCR office IP.
- If the AP was previously adopted to another controller/site, reset/adopt it in Omada after discovery works.

AP has AP management IP but GUI does not open:
- Check Network -> MikroTik -> AP Management -> Push Config. The system now detects active broad `/ip firewall raw action=notrack` rules and adds managed raw accept exceptions for the AP management subnet when needed.
- These exceptions keep AP GUI/control traffic connection-tracked without disabling or deleting the operator's existing raw rule.
- AP Management Push Config no longer adds office-to-AP GUI source NAT. It manages AP management VLAN transport, DHCP, Omada discovery/control reachability, and raw tracking exceptions only.
- If the AP management subnet was changed, re-open Push Config so stale managed raw exceptions are removed and the current subnet exceptions are shown.

Factory-reset AP does not receive AP management IP:
- Native/untagged AP-facing port automation is disabled for now.
- Manually enable the AP management VLAN inside the AP before deploying it to the station path.

Factory-reset AP should be adopted on office subnet first:
- Office AP Path is retired from the active UI. Connect the AP directly to the office subnet, adopt it in Omada, then set the AP management VLAN after adoption before moving it to the station path.
- If old Office AP Path RouterOS objects exist, remove them only after reviewing exact cleanup commands. Do not remove unmanaged VLAN/bridge objects by guess.
- In Network -> MikroTik -> AP Management, use tagged ports only for router-to-router, CRS, OLT, ONU, and AP-path trunk links.
- If a moved AP no longer appears in DHCP leases, confirm the AP is sending management traffic on the configured AP management VLAN and that every trunk in the path carries that VLAN.

MikroTik plan save says an IP/subnet/VLAN is already used:
- Run Network -> MikroTik -> Overview -> Prescan All Routers first so the system has current RouterOS state.
- The system blocks planned gateways/subnets that duplicate or contain existing MikroTik router API/management host IPs.
- Choose a new unused subnet/VLAN, or fix the saved MikroTik router host record if the router was added with the wrong access IP.
- Do not force-save a duplicate gateway IP; it can make Winbox/API open the wrong router or break return routing.

Edited AP Management or Station plan still has old RouterOS config:
- Open Push Config again. If the plan changed, the modal should show `Remove old config first` steps before the updated apply steps.
- The cleanup only targets system-managed names/comments from the previous plan.
- If old config was created manually or comments were changed outside the system, remove or reconcile it manually before pushing the updated plan.
- For central AP Management, only the root gateway owns the AP management subnet, gateway IP, pool, DHCP server, DHCP network, and Omada option 138. CRS/trunk routers only carry the VLAN tag. If you changed `10.88.0.0/24` to `10.55.0.0/24` but kept VLAN `88`, the CRS should still show VLAN `88`; it should not show an IP pool or DHCP subnet.

Omada Portal readiness shows `0/x APs connected`:
- The station modal now labels whether the count comes from live Omada API data or local saved AP records.
- If it says live Omada and `0/0`, Omada currently does not see APs in that site. Fix AP management discovery first.
- If it says local records, refresh/detect APs from Omada after the controller can see the APs.

AP briefly shows `Adopt Failed` before becoming connected:
- Confirm the AP state in Omada Controller first.
- AP adoption is now handled manually in Omada Controller. If Omada reports `Adopt Failed`, fix/retry adoption there.
- List of APs should mirror the Omada status instead of hiding it behind local adoption state.

AP is connected but implementation checklist is not complete:
- Open APs Deployment -> List of APs and click the AP row.
- Check the AP Implementation Checklist. `2/2` means WiFi SSIDs and SSID customer VLAN are complete.
- AP management VLAN is not auto-applied to the AP through Omada for now. Confirm Network -> MikroTik -> AP Management has been pushed, then manually set the AP management VLAN in the AP before station deployment.
- Device Account Credentials are no longer part of the required AP implementation checklist. They are not needed for the current Omada-managed SSID/VLAN/captive-portal flow.

AP adoption fails and Omada appears to change the AP username/password:
- AP adoption is now performed manually in Omada Controller, not in 3JCentralPisowifi.
- The system must not save AP login credentials, mark them applied, or send Omada `deviceAccountSetting` during site creation.
- If adoption fails because Omada needs the AP login, handle that in Omada Controller. If the AP login is unknown or was changed by older testing, factory-reset the AP first.

Sites configuration saved but AP WiFi/device settings did not change:
- This is expected. Saving APs Deployment -> Sites -> Configurations only stores the desired SSID/security strategy.
- Open APs Deployment -> List of APs and click `Push WiFi Config` for the site or AP when you want to push saved SSID/VLAN settings to connected APs.
- If the AP row says `FAILED`, hover/view the error and check AP configuration logs; Omada Controller may have rejected an existing SSID update path.
- If Omada rejects an existing SSID update, manually verify or update the SSID in Omada Controller until a supported API path is added for that controller version.
- Central AP management VLAN transport is configured from Network -> MikroTik -> AP Management. The AP's own management VLAN is manual for now and is not changed by 3JCentralPisowifi after adoption.

SSID was visible after adoption, then disappeared:
- Check List of APs and Omada Controller status. If the AP reports `Managed by Others`, `Disconnected`, or is no longer cleanly managed, the AP may have lost controller reachability after its management VLAN changed.
- Current workflow: manually configure the AP management VLAN in the AP before deploying it to the station path, then adopt it manually in Omada Controller.
- 3JCentralPisowifi no longer pushes the AP's own management VLAN through Omada after adoption. It applies SSIDs and the station/customer VLAN only when the operator clicks Push WiFi Config.
- If the AP was factory-reset and re-added with the same MAC, use List of APs -> Push WiFi Config after Omada reports Connected so SSID/VLAN settings are applied again.

AP stays in Omada `Configuring` for a long time:
- The system treats Omada status code `11` as `CONFIGURING`, not fully connected.
- While an AP is configuring, List of APs keeps the AP visible with a provisioning animation and does not mark the SSID/VLAN checklist as complete.
- If Omada stays in `Configuring`, focus on AP-to-controller reachability, AP management VLAN routing, and whether the AP can complete Omada config sync. SSIDs may not broadcast until Omada finishes applying the site configuration to the AP.
- A Configuring state should not repeatedly reset an already-applied AP checklist. If the AP flips Connected -> Configuring -> Connected, the system must not keep recreating the same SSIDs on every cycle.
- Check the MikroTik bridge host table for the AP MAC. If the AP management plan expects VLAN `88` but the AP MAC is learned on a different VID such as `201`, the AP is not actually using the AP management VLAN and the controller may show stale `Configuring`, `Pending`, or `Disconnected` state.
- A stale DHCP lease is not enough proof that the AP is reachable. If the CCR shows a bound lease but ARP is `complete=false`, the AP IP is historical/stale and the AP is not currently reachable through that management VLAN.

AP shows `Managed by Others`:
- Omada can see the AP IP, but this controller is not managing the AP configuration.
- SSIDs from the selected site will not broadcast while the AP is in this state.
- Factory reset the AP if needed, then adopt it again manually in Omada Controller.
