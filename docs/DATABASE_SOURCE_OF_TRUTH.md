# Database Source Of Truth

PostgreSQL remains the source of truth for 3JCentralPisowifi.

## Active Source-Of-Truth Records

- `admins`: admin users.
- `users`: portal/customer account records created for voucher access.
- `wallets`: remaining time, valid-until, and unlimited access state.
- `transactions`: wallet credits/debits, including voucher credits.
- `vouchers`: voucher code inventory and status.
- `voucher_redemptions`: successful and failed voucher redemption attempts.
- `portal_sessions`: browser/device portal context.
- `portal_events`: portal views, voucher submissions, successes, failures, and status checks.
- `portal_mac_rebind_events`: random/private-MAC device token reauthorization events.
- `omada_portal_authorizations`: Omada client authorization attempts.
- `captive_portal_settings`: portal URLs, current Omada captive portal settings, Portal Notifs switches, message templates, and remaining-time trigger seconds.
- `portal_design_templates`: customer portal HTML/CSS template.
- `mikrotik_routers`: RouterOS API connection records for station transport planning.
- `mikrotik_preflight_scans`: read-only scan snapshots used to validate VLANs/subnets/pools/DHCP/routing risks.
- `mikrotik_stations` and related station tables: reviewed station VLAN/DHCP/NAT/trunk transport plans.
- `ap_deployments` and AP deployment configuration tables: local AP/site/SSID configuration state.
- `omada_controller_settings` and `omada_install_logs`: old Omada install/manage automation state.
- `audit_logs`: operator/system audit trail.

## Voucher Rules

Vouchers are a credit source, not the final access source of truth after redemption.

- `vouchers.status` tracks `UNUSED`, `USED`, `EXPIRED`, `DISABLED`, or `VOIDED`.
- `voucher_redemptions.source = CLIENT_PORTAL` identifies customer portal redemption.
- Successful voucher redemption writes a wallet transaction.
- Wallet/access state remains the source of truth after voucher redemption.

## Portal Session Rules

Omada captive portal data is integration context, not the database of record.

- `portal_sessions` stores Omada redirect values, raw query params, authorization status, and access timestamps.
- `portal_sessions.device_token_hash` stores only a hashed browser device-session token used for random/private-MAC rebinds.
- `portal_events` stores user-visible portal activity and troubleshooting context.
- `omada_portal_authorizations` stores sanitized Omada API request/response summaries.
- `portal_mac_rebind_events` records old/new MAC, remaining time, status, and sanitized authorization summary when a token-based MAC rebind is attempted.

For Omada-sourced sessions, voucher redemption is committed only after Omada authorization succeeds.

## MikroTik Rules

MikroTik is not the source of truth for vouchers or wallet access.

MikroTik tables store:
- Router API credentials/settings.
- Read-only preflight scan data.
- Station transport plans.
- RouterOS command history for reviewed transport pushes/removals.

MikroTik HotSpot enforcement tables and legacy fields may remain historically, but they are not active in the current workflow.

## Historical Tables

Some old RADIUS/FreeRADIUS/NAS/accounting tables may remain in existing databases or migrations for history and audit compatibility. They are retired from the active UI/API and should not be used for current customer access.
