# Phase 1 Overview

Phase 1 originally built the operational foundation for 3JCentralPisowifi: Docker deployments, PostgreSQL, FastAPI, React Admin Portal, Omada Controller install/manage automation, users, Wallet, and early RADIUS lab tooling.

Those original access assumptions are historical. The active product direction has changed.

## Current Direction

The main customer flow is:

```text
Omada open SSID
-> Omada captive portal redirect
-> 3JCentralPisowifi /portal
-> Product Item / Physical Store / optional voucher claim
-> customer WiFi Bag item
-> Omada client authorization
-> internet access through MikroTik station transport
```

## Still Active

- PostgreSQL source-of-truth database.
- Admin Portal.
- Customer Devices and customer profiles.
- Product Items, Physical Stores, Sales, and optional Voucher management.
- Public client portal at `/portal`.
- Customer WiFi Bag items/events.
- Portal sessions and events.
- Omada Controller install/manage automation.
- Omada API settings, site detection, AP/SSID management, and captive portal actions.
- MikroTik router records, read-only preflight scans, AP management transport, and station VLAN/DHCP/NAT/trunk plans.

## Retired From Active Runtime

- Wallet / Manual Top-Up and wallet tables.
- FreeRADIUS runtime service.
- RADIUS auth/accounting packet tests.
- NAS/RADIUS client management.
- Sessions page based on RADIUS accounting.
- WPA2-Enterprise customer login and test SSID automation.
- OpenAI settings and AI Network Assistant workflows.
- MikroTik HotSpot enforcement, diagnostics, and managed `login.html`.
- Office AP Path transport.

Migration `117_cleanup_retired_wallet_ai_radius_hotspot.sql` removes the retired persistence layer. The legacy `sessions` table is temporarily retained only as a Customer Devices fallback/history source.

## Omada Controller

Omada Controller remains important. The old install/manage automation must stay available because it installs and controls the separate controller server at `192.168.50.71`.

Omada manages APs, sites, open SSIDs, portal redirect, and client authorization. It does not own customer profiles, WiFi Bag access time, vouchers, payments, store approvals, or sales.

## MikroTik

MikroTik remains active for network transport:

- Customer VLANs.
- DHCP pools/networks.
- NAT/routing.
- AP management VLAN/subnet.
- CRS/switch/trunk path planning.
- Preflight scans to detect conflicting VLANs, subnets, pools, DHCP, PPPoE, OSPF, WireGuard, routes, firewall/NAT, and old HotSpot objects.

MikroTik is not the captive portal enforcement layer in the current workflow. Omada is.

## Not Included Yet

- Coinslot/vendo integration.
- WireGuard automation.
- Production rollout automation.
