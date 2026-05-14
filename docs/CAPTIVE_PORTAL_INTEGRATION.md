# Captive Portal Integration

Phase 2C connected the public voucher portal to Omada captive portal testing. The current production direction is MikroTik gateway enforcement with Omada kept for AP/SSID management.

## Flow

1. Customer connects to the open SSID configured in `APs Deployment -> Sites -> Configurations -> SSID and Security`.
2. Omada redirects the browser to `http://192.168.50.70:8080/portal`.
3. The portal captures Omada client parameters.
4. Customer enters a voucher.
5. 3JCentralPisowifi validates the voucher.
6. If the request came from Omada, the system attempts Omada client authorization.
7. When authorization succeeds, the voucher is redeemed and wallet/access is credited.

## Omada Role

Omada manages APs, SSIDs, captive portal redirect, and client authorization. It does not manage customer accounts, vouchers, wallets, or access decisions.

## MikroTik Gateway Direction

MikroTik is the preferred captive portal enforcement layer for future substations.

Recommended split:

- Omada: AP adoption, SSIDs, radio settings, VLAN tagging, AP monitoring.
- MikroTik: captive portal redirect, HotSpot enforcement, RADIUS accounting, queues/rate limits, routing, and future WireGuard tunnels.
- 3JCentralPisowifi: vouchers, wallets, portal sessions, access decisions, and logs.

MikroTik management now lives under `Admin -> Network -> MikroTik`, where operators can store multiple RouterOS API connection records, test API login/reachability, run read-only scans, and plan station router chains.

Use a dedicated full/write RouterOS API account. MikroTik captive portal automation needs write access for HotSpot, walled garden, client authorization, and portal enforcement. Do not use the main MikroTik admin account.

The MikroTik workspace is split into `Configuration` and `Add Router`. Add and test router API credentials in `Add Router`; then use `Configuration` to run/read scan status, view scan results per router, and create station plans. The main Configuration table no longer shows the old single-router `Start Setup`, `Check Config`, or `Remove Config` actions because station planning is now the active workflow. Future apply/remove phases must still show exact RouterOS commands before any RouterOS write is sent.

Station planning is now the preferred way to model real deployments. A station is an ordered router path: the first router is the root gateway and the next routers carry the same customer VLAN as trunk helpers toward CRS, OLTs, switches, and APs. The Add Station modal starts with an empty chain, then operators add routers one by one. Each router appears as a vertical tab with a router icon and drag indicator; selecting a router tab opens that router's bridge/tagged-port setup, and dragging tabs changes router order. The left chain includes an animated root-to-downstream pulse to show the intended VLAN flow. The validated reference pattern is `ACroma -> CRS317` with VLAN 77: the root gateway creates `VLAN77-3J-HOTSPOT`, `10.77.0.1/24`, the DHCP pool/network options, and `LOCAL` interface-list membership; the CRS adds a bridge VLAN trunk for the same VLAN toward OLT/AP ports. Saving a station plan does not apply RouterOS configuration.

For station setup, the operator should not need to understand RouterOS command syntax. The Add Station modal is organized as a checklist: name the station, build the router chain, fill detected router bridge/tagged-port fields, fill root gateway network values, and review the generated plan. The selected router panel is split into `Step 3A: Select Router`, `Step 3B: Select Root Bridge and Tagged Ports`, and, for the root gateway only, `Step 3C: Root Gateway Network Values`. `Step 4: Review Plan` appears after the operator clicks `Save & Review Station Plan`; saving shows generated RouterOS preview text only and still does not apply configuration. Operators explicitly choose each saved router in the path, while bridge/interface, tagged ports, and root local interface list are selected from read-only RouterOS-detected controls to reduce typing mistakes. Tagged ports use a searchable checkbox list so operators can select multiple trunk/OLT/AP-facing ports without holding Ctrl/Command. Station bridge/interface and tagged-port selectors hide PPPoE interfaces because the VLAN should be created/carried on bridges, trunks, or physical ports such as `SwAC`, not on dynamic/customer PPPoE sessions. Field-level info icons explain what each value means. The root gateway tab owns the customer VLAN, gateway subnet, DHCP pool, DNS servers, VLAN interface name, and local interface-list membership. Downstream router tabs only choose the detected bridge/interface and tagged ports needed to carry the VLAN. The system must not silently reuse existing RouterOS pools, subnets, profiles, speed-plan configuration, management interfaces, or WAN settings.

The system must create only system-owned RouterOS objects from those entered values. It must not silently reuse existing RouterOS pools, subnets, profiles, speed-plan configuration, management interfaces, or WAN settings. New RouterOS records should use the System Display Name as the identifier where possible and must include managed comments so operators can immediately recognize configuration created by 3JCentralPisowifi.

Captive Portal does not have its own editable SSID field. It reads the SSID from APs Deployment -> Sites -> Configurations -> SSID and Security so AP/SSID management has one source.

The Captive Portal page no longer has a separate Omada Integration tab. Keep Omada-specific controller, AP, SSID, and lab automation under Omada Controller and APs Deployment. Captive Portal should stay focused on MikroTik gateway setup, portal settings/design, sessions, logs, and manual operator guidance.

The `Sanity Check` tab replaces the old test-flow checklist. It combines automatic readiness checks, manual field-test confirmations, and `Coming soon` placeholders for features that are intentionally not complete yet, such as MikroTik client authorization, login page upload, payments, SMS, and coinslot/vendo integration.

## Portal URLs

Staging:

```text
http://192.168.50.70:8080/portal
```

Production:

```text
http://192.168.50.70/portal
```

## Query Parameters

The portal accepts Omada-style parameters such as:

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

Raw query parameters are stored with the portal session for diagnostics.

## Authorization Behavior

Manual portal testing does not require Omada authorization. Omada-sourced sessions validate the voucher first, then attempt authorization. If Omada authorization fails, the voucher is not consumed.

Unlimited vouchers without an expiry use the configured default authorization duration. The default fallback is 86400 seconds.

## Manual Omada Setup

1. Open `https://192.168.50.71:8043`.
2. Create or edit the WLAN using the SSID configured in APs Deployment -> Sites -> Configurations.
3. Set security to Open.
4. Enable Captive Portal / Portal Authentication.
5. Choose External Portal / External Web Portal.
6. Set portal URL to `http://192.168.50.70:8080/portal` for staging.
7. Add walled garden access for `192.168.50.70`, the portal URL, and DNS if required.
8. Apply to one test AP only.
9. Connect a phone and redeem one test voucher.

## Troubleshooting

Omada API login failed:
- Check Omada username/password.
- Confirm Omada first-time setup is complete.
- Disable TLS verification for lab self-signed certificates if needed.

Client did not redirect:
- Confirm captive portal is enabled on the open SSID.
- Confirm the SSID is applied to the test AP.
- Confirm walled garden allows the portal server.

Voucher valid but authorization failed:
- Check Admin -> Captive Portal -> Authorization Logs.
- Confirm Omada sent client MAC/token parameters.
- Use the manual Omada setup guide if API automation is unsupported by this controller version.

Client authorized but no internet:
- Check gateway/DNS routing outside 3JCentralPisowifi.
- Confirm Omada portal policy allows internet after authorization.

## Not Implemented Yet

- Payments.
- SMS.
- Coinslot/vendo integration.
- Full MikroTik client authorization and managed login page upload.
- WireGuard tunnel automation.
- Production rollout automation.

## MikroTik Preflight Before Setup

Admin -> Network -> MikroTik no longer has a standalone `Preflight Scanner` tab. Read-only scan controls are now surfaced in `Configuration`.

Run `Prescan All Routers` or `Run Scan` from the Configuration router table before MikroTik captive portal setup. The scan is read-only and checks existing VLANs, subnets, pools, DHCP servers, HotSpot servers, PPPoE, OSPF, WireGuard, routing, firewall/NAT summaries, and unsupported RouterOS paths. Use `View Scan Result` in the router table to open the result in a new browser tab/page. The scan-result page uses vertical section tabs with large icon badges for the scan sections; Overview includes role explanation, findings by category, and scan history.

The scanner gives:

- router identity/model/version
- advisory router role guess
- risk level
- conflict warnings
- recommended next questions

AI explanation has been removed from the active workflow. Future apply phases must still show exact command previews and require explicit operator approval.

## MT-2 Safe MikroTik Readiness

Network -> MikroTik -> Configuration now includes the latest scan summary, `Prescan All Routers`, per-router `Run Scan`, and per-router `View Scan Result`.

The active UI no longer shows deployment-mode confirmation or policy-decision cards. Operators review scan results directly and use station planning fields to create the router chain. Add Station is disabled until read-only scan data exists.

## Manual MikroTik Setup Refocus

The AI Network Assistant, AI chat, AI smoke test, AI suggested answers, and AI draft plans have been removed from the active UI.

The active workflow is now:

1. Add MikroTik routers under Network -> MikroTik -> Add Router.
2. Return to Network -> MikroTik -> Configuration.
3. Run Prescan All Routers or scan the needed router from the table.
4. Open View Scan Result for any router that needs review.
5. Use Add Station to build the ordered router chain.
6. Enter the required customer VLAN, parent interface, client subnet, gateway, DHCP pool, DNS, and local interface-list values in the station modal.
7. Use scan data to avoid VLAN/subnet/pool conflicts before any future reviewed apply step.

## MT-3.3 VLAN Path Planning

PPPoE access concentrators are high-risk but valid HotSpot Gateway candidates when the captive portal network uses a new dedicated VLAN/subnet and existing PPPoE, OSPF, WireGuard, routing, and production bridge objects remain protected.

Before MT-4 command preview, the pilot router must have a confirmed VLAN Path Planner record. The planner describes the gateway parent bridge/trunk, the first next-hop device after the gateway, CRS involvement, OLT behavior, and AP tagged/untagged VLAN mode. The open captive portal SSID uses the same customer VLAN ID from the planning questions, so there is no separate SSID VLAN field. The system does not guess `ether1` or another physical interface unless the scan and operator-confirmed topology prove the AP/customer VLAN path.

Large pilot client subnets bigger than `/22` are allowed only with a warning. For first-router testing, use `/24` or `/22` unless the operator intentionally needs more client addresses.
