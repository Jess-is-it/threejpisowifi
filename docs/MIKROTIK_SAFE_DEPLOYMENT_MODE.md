# MikroTik Transport Safety Mode

The active MikroTik workflow is now station transport, not captive portal enforcement.

MikroTik is used to build and validate station VLAN, DHCP, NAT, AP-management, and trunk paths. Omada handles the open SSID captive portal redirect and client authorization. 3JCentralPisowifi remains the source of truth for Product Items, Physical Store approvals, optional vouchers, WiFi Bag access, portal sessions, and access decisions.

## Purpose

The system must not blindly configure production MikroTik routers. Read-only preflight scans are required before station plans because they let the system validate user-entered VLANs, IP networks, DHCP pools, interfaces, and existing router risks.

## Active Safety Model

The active operator flow is:

1. Add saved MikroTik routers.
2. Run `Prescan All Routers` or scan an individual router.
3. Review scan results from `Network -> MikroTik -> Configuration`.
4. Create or edit a station router chain.
5. Review the station push modal.
6. Push station transport or AP-management config step by step.

No AI recommendation, OpenAI workflow, RADIUS workflow, or MikroTik HotSpot enforcement is part of the active path.

## What Preflight Protects

Preflight data is used to catch:

- VLAN ID already present on the selected router.
- Client or AP-management subnet overlap.
- DHCP pool overlap.
- Missing bridge/interface or selected interface that was not found in the latest scan.
- PPPoE interfaces selected for VLAN transport.
- RouterOS text or unsupported path issues.
- Core/routing/OSPF/WireGuard sensitivity that should be reviewed by an operator.

The scanner is read-only. It does not add, remove, or edit RouterOS configuration.

## Station Router Chains

A station is an ordered router path.

- The first router is the root gateway for the station network.
- The root creates the station customer VLAN interface, gateway IP, DHCP pool/network options, local-interface membership, a WAN-only station NAT rule, and a no-NAT exception to the Omada/portal office subnet.
- The no-NAT exception is required for Omada captive portal because the controller must see the real client IP/MAC context, not the MikroTik gateway IP created by broad masquerade.
- The root also creates station-scoped one-device voucher fairness rules. Return traffic to customer devices is TTL-clamped and common tethered TTL values are dropped so normal phone hotspot sharing does not extend one voucher to another hidden device. If FastTrack is active, station-scoped established/related accept rules are inserted before FastTrack so the TTL guard remains effective.
- Downstream routers carry the same VLAN as tagged transport toward CRS, OLT, ONU, and AP paths.
- The station modal uses detected RouterOS interfaces and ports instead of free-text interface names.
- PPPoE interfaces are hidden from bridge/interface and tagged-port selections.
- Tagged ports use searchable checkboxes.
- Saving a station plan stores the plan and review data. It does not push configuration until the operator opens `Push Config`.

## AP Management

Central AP management is a separate transport plan. It uses its own VLAN/subnet and is configured from `Network -> MikroTik -> AP Management`.

The system validates AP-management values against:

- existing router subnets from preflight scans
- existing IP pools
- existing station customer VLANs
- selected bridge/interface existence
- selected tagged-port existence

When an AP-management plan is edited, the push modal should show any old system-managed configuration that must be removed before the new configuration is pushed.

## Retired Policy Screens

The old standalone Preflight Scanner tab, Policy Decision card, Deployment Mode Confirmation, Expert Override, AI Network Assistant, AI Explain, AI chat, and AI draft-plan workflows are retired from the active UI.

Historical policy tables or code may remain for migration compatibility, but they are not the operator workflow.

## Retired MikroTik HotSpot Work

The system no longer uses MikroTik HotSpot as the active captive portal enforcement layer.

Do not restore these active surfaces unless the project owner explicitly asks:

- MikroTik HotSpot profile/server setup
- MikroTik managed `login.html` sync
- MikroTik HotSpot client authorization
- HotSpot diagnostics as the primary portal path
- RouterOS command preview based on AI planning

## Manual Validation Rules

Before station or AP-management config can be pushed, the system should validate:

- VLAN ID is numeric and non-conflicting for the selected router.
- IPv4 CIDR is valid.
- Gateway IP is inside the CIDR and is not network or broadcast.
- DHCP pool start/end are inside the CIDR.
- Pool start is lower than pool end.
- Pool does not include the gateway.
- DNS entries are valid IP addresses.
- NAT must be scoped to WAN only. Station clients must not be masqueraded when they reach the Omada Controller or 3J portal server on the office subnet.
- One-device voucher fairness rules must be scoped to the station client subnet/VLAN interface and removed only by exact managed comments.
- Selected bridges/interfaces/ports exist in the latest scan.

These deterministic checks are the safety gate for the current manual workflow.
