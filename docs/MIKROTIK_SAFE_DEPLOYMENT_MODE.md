# MikroTik Safe Deployment Mode

Phase MT-2 adds a deterministic policy layer between read-only router scanning and any future RouterOS command preview or apply workflow.

## Purpose

The system must not blindly configure MikroTik routers. The backend keeps policy/risk logic for validation, but the active operator UI now focuses on read-only scan review plus station planning instead of deployment-mode confirmation screens.

## Deployment Modes

- `HOTSPOT_GATEWAY`: the router may host a dedicated customer VLAN/interface, DHCP, HotSpot server, walled garden, and optional NAT in a future phase.
- `VLAN_TRUNK_HELPER`: the router or CRS/switch only carries VLAN traffic to APs. It should not host HotSpot, DHCP, or NAT.
- `READ_ONLY_CORE`: the router appears to be core or ISP-sensitive. It should not be configured for captive portal by this system.
- `ISP_BACKUP_TRANSPORT`: the router is transport/backup/tunnel-oriented. It should remain scan-only for captive portal work.
- `UNKNOWN_NEEDS_REVIEW`: not enough information exists. A user must confirm the role before setup can continue.

## Policy Engine Behavior

The policy engine evaluates:

- latest successful preflight scan
- RouterOS identity/model/version
- VLANs, subnets, IP pools, DHCP, HotSpot, PPPoE, OSPF, WireGuard, routes, firewall, and NAT indicators
- proposed MikroTik captive portal fields saved on the router record
- confirmed router role and deployment mode, if legacy data exists
- expert override status, when required

The engine returns risk level, role guess, recommended mode, setup allowed/blocked, blocking reasons, warnings, and next questions.

## MT-2.1 Role Rules

PPPoE access concentrators are high risk but not automatically read-only/core. They may be considered for future HotSpot Gateway only if captive portal traffic is isolated on a new dedicated VLAN/subnet/interface.

Core routers remain read-only/core. The classifier requires multiple strong core indicators before recommending `READ_ONLY_CORE`.

CRS/switch/trunk devices should use `VLAN_TRUNK_HELPER`. They should not host HotSpot, DHCP, or NAT for the captive portal.

Failed scans are treated as `UNKNOWN_NEEDS_REVIEW` and `NOT_RECOMMENDED` for pilot selection until a clean scan succeeds.

## When Setup Is Blocked

Setup is blocked when:

- no successful preflight scan exists
- router appears core/read-only or transport-only
- a CRS/switch is selected for HotSpot Gateway
- proposed customer VLAN already exists
- proposed client subnet overlaps an existing router network
- proposed DHCP pool overlaps an existing pool
- required HotSpot Gateway fields are missing
- NAT is enabled without a WAN interface
- a high-risk HotSpot Gateway confirmation or expert override is required but missing

## Expert Override

Expert override is a recorded risk acceptance only. It requires the exact phrase `I UNDERSTAND THE RISK`, an override reason, admin identity, and timestamp.

Expert override does not:

- apply MikroTik configuration
- bypass missing required fields
- bypass VLAN/subnet/pool overlap blockers
- delete unmanaged RouterOS objects
- allow hidden or unreviewed commands

## Prescan All Routers

`Prescan All Routers` runs read-only scans across every saved MikroTik router with limited concurrency. Failed or unreachable routers do not stop the batch. The Configuration tab uses the batch and each router's latest scan to show current scan status.

## AI Removed

The AI Network Assistant, AI explain, AI chat, AI planning suggestions, and AI draft-plan features are no longer part of the active workflow.

The deterministic policy engine remains the authority for manual MikroTik setup. Preflight data is still used to warn or block unsafe values before an operator applies an individual reviewed setup step.

## Command Preview Readiness Requirements

Before MT-4 command preview, the selected pilot must have:
- successful latest preflight scan
- required manual MikroTik setup fields saved
- valid VLAN ID, CIDR, gateway, DHCP pool, DNS list, NAT decision, and WAN interface when NAT is enabled
- no hard safety policy blockers

The current UI is focused on manual setup under `Admin -> Network -> MikroTik -> Configuration`. The UI no longer shows the standalone Preflight Scanner tab, `Policy Decision`, or `Deployment Mode Confirmation`; scan results are opened from the Configuration router table in a new browser tab/page with vertical section tabs and large icon badges.

## Manual Field Validation

The safety engine validates:
- customer VLAN does not already exist on the selected router
- client CIDR is valid IPv4 and large enough for DHCP
- gateway is inside CIDR and is not network/broadcast
- DHCP pool is inside CIDR
- DHCP pool start is lower than pool end
- DHCP pool does not include the gateway IP
- client subnet does not overlap existing router subnets
- DHCP pool does not overlap existing pools
- DNS entries are valid IP addresses
- NAT `yes` requires a WAN/interface selection

No AI suggestion can bypass these checks because AI is no longer part of the active workflow.

## Station Router Chains

`Network -> MikroTik -> Configuration` includes station planning for multi-router deployments. A station is an ordered VLAN path:

- router 1 is the root gateway that creates the customer VLAN interface, gateway IP, DHCP pool/network options, and local interface-list membership
- routers 2+ are trunk helpers that carry the same VLAN across CRS/switch/transport paths toward OLTs and APs
- order matters, so the UI allows the operator to rearrange routers before saving the plan
- the Add Station modal uses vertical router tabs with router icons, grey drag indicators, and grab cursors for per-router setup, plus an animated root-to-downstream pulse to show VLAN flow
- the Add Station modal includes an operator checklist and info icons for each major field so non-MikroTik users understand what they are selecting
- selected-router setup is split into Step 3A router selection, Step 3B bridge/tagged-port selection, and root-only Step 3C network values
- Step 4 review appears only after saving the station plan and shows RouterOS preview text without applying it
- root-only network values are displayed inside the root gateway tab; downstream router tabs do not show VLAN IP/DHCP fields because they only carry the selected VLAN
- bridge/interface, tagged ports, and root local interface list are selected from read-only RouterOS-detected dropdowns instead of free-text fields
- bridge/interface and tagged-port choices hide PPPoE interfaces so station plans do not create or carry customer VLANs on PPPoE sessions
- tagged ports use searchable checkboxes rather than Ctrl/Command multi-select
- the old single-router `Start Setup`, `Check Config`, and `Remove Config` actions are no longer shown in the main Configuration table
- saving a station plan only stores the plan and generated review commands; it does not apply RouterOS changes

The current validated reference is VLAN 77 through `ACroma -> CRS317`, where ACroma owns `VLAN77-3J-HOTSPOT` and `10.77.0.1/24`, and CRS317 carries VLAN 77 on tagged ports toward OLT/AP paths.

## MT-3.3 VLAN Path Safety

PPPoE access concentrators are treated as possible HotSpot Gateway candidates with caution, not automatically as read-only/core. The policy remains strict:
- risk stays high
- PPPoE/OSPF/WireGuard/routing objects are protected
- deployment mode must be confirmed
- HotSpot planning must use a new dedicated VLAN/subnet
- command preview remains blocked until safety checks pass

Router role and deployment mode are intentionally separate. Router role describes what the MikroTik currently does, such as `PPPoE_ACCESS_CONCENTRATOR`. Deployment mode describes what 3JCentralPisowifi plans to do later, such as `HOTSPOT_GATEWAY`. A PPPoE access concentrator can therefore stay high-risk while still being a possible HotSpot Gateway pilot if the new captive portal network is isolated.

VLAN parent interface selection is high risk. The system must not silently use a physical interface such as `ether1` unless the AP/customer VLAN path is confirmed. The VLAN may traverse CRS switches, OLTs, ONUs, and AP uplinks before reaching Omada APs. `Next Hop Device` means the first device after the HotSpot gateway on that path.

The VLAN Path Planner must be confirmed before MT-4. It validates CRS involvement, OLT behavior, AP tagged/untagged VLAN mode, the single customer VLAN ID used by the open SSID, and gateway parent interface selection. Large pilot subnets bigger than `/22` are allowed only with a warning.
