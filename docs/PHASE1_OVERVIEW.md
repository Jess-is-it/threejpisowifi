# Phase 1 Overview

Phase 1 originally built the operational foundation for 3JCentralPisowifi: Docker deployments, PostgreSQL, FastAPI, React Admin Portal, Omada Controller install/manage automation, users, wallets, and early lab authentication tooling.

The active product direction has changed.

## Current Direction

The main customer flow is:

```text
Omada open SSID
-> Omada captive portal redirect
-> 3JCentralPisowifi /portal voucher entry
-> voucher/wallet validation
-> Omada client authorization
-> internet access through MikroTik station transport
```

## Still Active

- PostgreSQL source-of-truth database.
- Admin Portal.
- Users and wallets.
- Voucher management and redemption logs.
- Public client portal at `/portal`.
- Portal sessions and events.
- Omada Controller install/manage automation.
- Omada API settings, site detection, AP/SSID management, and captive portal actions.
- MikroTik router records, read-only preflight scans, AP management transport, and station VLAN/DHCP/NAT/trunk plans.

## Retired From Active Runtime

- FreeRADIUS runtime service.
- RADIUS auth/accounting packet tests.
- NAS/RADIUS client management.
- Sessions page based on RADIUS accounting.
- WPA2-Enterprise customer login and test SSID automation.
- OpenAI settings and AI Network Assistant workflows.
- MikroTik HotSpot enforcement, diagnostics, and managed `login.html`.

Historical tables, migrations, and notes may still exist, but the active UI/API should not expose those retired workflows.

## Omada Controller

Omada Controller remains important. The old install/manage automation must stay available because it installs and controls the separate controller server at `192.168.50.71`.

Omada manages APs, sites, open SSIDs, portal redirect, and client authorization. It does not own vouchers or wallets.

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

- Payments.
- SMS.
- Coinslot/vendo integration.
- WireGuard automation.
- Production rollout automation.
