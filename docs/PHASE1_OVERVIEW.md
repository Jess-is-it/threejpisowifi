# Phase 1 Overview

Phase 1 builds the operational foundation for 3JCentralPisowifi.

Current product direction: Captive Portal + Voucher access is now the main customer flow. WPA2-Enterprise username/password WiFi login remains available only as an advanced/lab validation path.

It includes:
- One-line Ubuntu install and update.
- Separate production and staging deployments.
- PostgreSQL source-of-truth schema.
- FastAPI backend.
- React Admin Portal.
- FreeRADIUS authentication and accounting helpers.
- Manual user creation and manual time balance.
- NAS / Router / AP client records.
- Session tracking and single-device rejection.

Phase 1C adds real RADIUS Accounting Start, Interim-Update, and Stop support. Accounting packets create active sessions, update last seen/device metadata, deduct wallet time through ACCOUNTING DEBIT transactions, and close sessions on Stop. Active accounting sessions are now the basis for single-device rejection.

Phase 1D adds External Omada Controller Server setup. The Omada Controller runs on a separate server at `192.168.50.71` for isolation and manages Omada APs, SSIDs, WiFi profiles, and RADIUS profile assignment only. 3JCentralPisowifi on `192.168.50.70` remains the source of truth for users, wallets, sessions, accounting, and access decisions.

Admin test paths:
- Simulated RADIUS Decision Test: backend-only source-of-truth decision check.
- Real FreeRADIUS Authentication Test: real Access-Request from API container to FreeRADIUS.
- Real RADIUS Accounting Test: real Accounting-Request packets for Start, Interim-Update, and Stop.
- Omada AP preparation: install/manage Omada Controller by controlled SSH actions, create a test NAS client, and follow the real AP checklist.

Main operator direction:
- Customers connect to an open SSID.
- Captive Portal opens.
- Customer enters a voucher code.
- 3JCentralPisowifi validates the voucher and grants time/access.
- Wallet/session/accounting logic remains in 3JCentralPisowifi.

It does not include coinslot, vendo, SMS, online payments, self-registration, dynamic VLAN, deep controller automation, WireGuard automation, production captive portal flow, or HA clustering.

## Phase 1E Summary

Phase 1E adds optional Omada API automation for real AP testing. It stores Omada API settings securely, tests API login, detects Omada sites, creates the matching 3JCentralPisowifi NAS trust entry, and attempts to create an Omada RADIUS profile and test WPA2-Enterprise SSID.

3JCentralPisowifi remains the source of truth for users, wallets, sessions, accounting, and access decisions. Omada only manages AP and WLAN configuration. Manual fallback values are always shown because Omada API endpoints can vary by controller version.

## Captive Portal Priority Update

WPA2-Enterprise testing is parked as an advanced/lab feature. The next major feature is Voucher Management, followed by customer-facing Captive Portal integration. Omada remains useful for AP and SSID management, while FreeRADIUS/accounting remains useful as the backend session/accounting foundation.

## Phase 2A Started

Phase 2A starts Voucher Management. Admins can create single vouchers, bulk generate voucher batches, track status and expiry, export/print codes, and test redeem vouchers into customer wallets. Captive portal enforcement and public customer redemption UI are still future phases.

## Phase 2B Started

Phase 2B adds the public client portal at `/portal`. Customers can manually enter voucher codes, portal sessions/events are logged, and successful redemption credits access through the existing voucher and wallet system. WiFi redirect and internet enforcement remain future integration work.

## Phase 2C Started

Phase 2C adds Omada Captive Portal integration for one-AP testing. The public portal captures Omada redirect parameters, validates vouchers, attempts Omada client authorization, and records authorization logs. If Omada authorization fails, the voucher is not consumed. Manual Omada setup instructions remain available because controller API behavior can vary by version.

## MikroTik Captive Portal Direction

The preferred production captive portal design is now MikroTik as the gateway/enforcement layer and Omada as AP/SSID management only. Admin -> Network -> MikroTik is used for adding multiple RouterOS gateways, testing API login/reachability, running preflight scans, and planning station router chains before any reviewed RouterOS changes. Full MikroTik HotSpot automation, WireGuard tunnel automation, payments, SMS, and coinslot/vendo integration remain future work.
