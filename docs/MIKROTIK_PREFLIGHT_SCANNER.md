# MikroTik Read-Only Preflight Scans

Phase MT-1 adds a read-only scanner for MikroTik routers before captive portal setup.

## Purpose

The scanner helps operators and future automation understand a MikroTik before any configuration is prepared. It is designed for 3JCentralPisowifi and for other ISP layouts where routers may already have PPPoE, VLAN trunks, OSPF, WireGuard, HotSpot, DHCP, pools, firewall rules, or public routing.

The scanner does not change the router.

## What It Checks

The backend uses RouterOS API read-only print calls where available:

- system identity and resources
- interfaces, bridges, bridge ports, and bridge VLANs
- VLAN interfaces
- IP addresses and subnets
- IP pools
- DHCP servers and networks
- HotSpot servers and profiles
- firewall filter and NAT summary
- routes
- OSPF indicators, if supported by the RouterOS version
- RADIUS entries
- WireGuard indicators
- PPPoE server indicators

Unsupported RouterOS paths are recorded as warnings instead of failing the whole scan.

## Conflict Detection

The scanner detects:

- proposed customer VLAN already exists
- proposed client subnet overlaps an existing subnet
- proposed DHCP pool overlaps an existing pool
- DHCP server already exists on the target interface
- existing HotSpot servers/profiles
- PPPoE access concentrator risk
- OSPF/routing sensitivity
- WireGuard/tunnel sensitivity
- core router/public IP risk
- CRS or VLAN-switching device risk

Risk levels are `LOW`, `MEDIUM`, `HIGH`, and `BLOCKED`.

## Role Guess

Role guess is advisory only. Current role guesses:

- `HOTSPOT_GATEWAY_CANDIDATE`
- `PPPoE_ACCESS_CONCENTRATOR`
- `CORE_ROUTER_READ_ONLY`
- `SWITCH_TRUNK_HELPER`
- `ISP_BACKUP_TRANSPORT`
- `UNKNOWN_NEEDS_REVIEW`

The active operator UI does not require deployment-mode confirmation. Role guesses remain useful context for scan review, but station planning is the primary setup workflow.

## AI Features Removed

The Preflight Scanner no longer has `AI Explain Scan` or any OpenAI dependency.

The scanner remains fully useful without AI. It stores sanitized read-only RouterOS data so the manual MikroTik setup workflow can validate operator-entered VLAN IDs, subnets, pools, interfaces, and protected-router indicators.

## Safety Model

The intended future workflow is:

1. Add saved MikroTik routers.
2. Run read-only scans from `Network -> MikroTik -> Configuration`.
3. Review scan results from the router table.
4. Build a station router chain.
5. Exact command preview in a future apply phase.
6. Step-by-step apply in a future apply phase.

No AI step is part of the active workflow.

## Operator Guidance

Run a scan before starting MikroTik setup. Resolve blockers before continuing. If PPPoE, OSPF, public routing, or existing production HotSpot configuration is detected, treat the router as high risk and confirm with a network engineer before any future apply phase.

## Current Configuration UI

Admin -> Network -> MikroTik no longer has a standalone `Preflight Scanner` tab. The Configuration tab now has:

- latest scan summary/status
- `Prescan All Routers`
- per-router `Run Scan`
- per-router `View Scan Result`, which opens `/admin/network/mikrotik/scan-result?router_id=...` in a new browser tab/page
- Add Station disabled until the operator has engaged read-only scanning

`Prescan All Routers` is read-only. It creates a scan batch, scans each saved MikroTik router with limited concurrency, stores one scan result per router, and continues when one router fails.

The Configuration router table shows:

- router API status
- latest preflight risk/status/timestamp
- detected role guess
- scan actions

The scan-result page shows a vertical section navigator with large icon badges. Sections include:

- Overview
- Conflicts
- VLANs
- Subnets
- Pools
- DHCP
- HotSpot
- Sensitive indicators

Role explanation, findings by category, and scan history are shown inside the Overview section so the operator sees the main scan context without switching tabs.

The scan-result page displays:

- latest scan identity/model/version
- existing VLANs, subnets, pools, DHCP, HotSpot, and sensitive indicators
- findings by category and scan history

## Policy Data

Policy/risk engine data may still exist in the backend for validation, but the active UI no longer shows `Policy Decision`, `Deployment Mode Confirmation`, or expert override cards. Operators review scan results directly and then create station plans.

## MT-2.1 Stabilization

The scanner now sanitizes all RouterOS text before storing scan data in PostgreSQL:

- null bytes are removed
- invalid surrogate characters are replaced
- non-printable control characters are removed except normal whitespace
- secrets are still redacted
- JSON serialization is checked through the same safe value pipeline used for database writes

This prevents failures such as PostgreSQL rejecting `\u0000` in RouterOS comments, interface names, route comments, firewall comments, DHCP fields, or other response data.

## MT-2.1 Role Tuning

PPPoE access concentrators are now classified as `PPPoE_ACCESS_CONCENTRATOR`, not automatically as read-only/core. They remain high risk, but captive portal gateway mode may be possible later only on a new dedicated VLAN/subnet/interface after confirmation.

Core routers are classified as `CORE_ROUTER_READ_ONLY` only when multiple strong core indicators exist, such as public IPs, core naming, many routes, multiple default routes, or OSPF/routing sensitivity.

CRS/switch devices are classified as `SWITCH_TRUNK_HELPER` and recommended for `VLAN_TRUNK_HELPER`, not HotSpot Gateway.

Each scan now includes role reasoning, deployment reasoning, and pilot suitability:

- `GOOD_PILOT`
- `POSSIBLE_WITH_CAUTION`
- `NOT_RECOMMENDED`
- `UNKNOWN`

## Manual Setup Refocus

The AI Network Assistant, AI chat, AI smoke test, AI planning suggestions, and AI draft plan workflows have been removed from the active UI.

The active path is now:

1. Add MikroTik router API credentials.
2. Open `Network -> MikroTik -> Configuration`.
3. Run Prescan All Routers or scan a router from the table.
4. Open `View Scan Result` for the router that needs review. It opens in a new browser tab/page.
5. Use `Add Station` after scan data exists.
6. Enter the required root gateway VLAN, client subnet, gateway, DHCP pool, DNS, local interface list, and per-router bridge/tagged ports in the station modal.
7. Let deterministic validation use preflight data to warn about conflicts.
8. Review and apply individual MikroTik setup steps only when a future apply phase is ready.
