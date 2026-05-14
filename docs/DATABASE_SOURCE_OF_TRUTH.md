# Database Source Of Truth

PostgreSQL is the source of truth for Phase 1.

The system stores admins, users, wallets, NAS/router/AP clients, transactions, RADIUS auth logs, sessions, and audit logs in PostgreSQL. FreeRADIUS reads and updates PostgreSQL through helper scripts and compatible SQL tables.

Phase 1C accounting source-of-truth rules:
- `sessions` records the current and historical online state for users.
- `radius_accounting_logs` stores every Accounting Start, Interim-Update, and Stop diagnostic.
- `wallets.time_remaining_seconds` is deducted only from accounting elapsed time.
- `transactions` records ACCOUNTING DEBIT rows for wallet time deductions.
- `radacct` may remain available for FreeRADIUS compatibility, but application session state is bridged into the custom `sessions` table.

Network devices are RADIUS clients. They must not become the user database.

## Phase 2A Voucher Source Rules

Vouchers are a credit source, not the final source of truth after redemption.

- `vouchers` stores prepaid codes and their status.
- `voucher_redemptions` stores every successful or failed redemption attempt.
- `transactions` records successful voucher credits with `source = VOUCHER`.
- `wallets` remains the source of truth for remaining time, valid-until access, and unlimited access.
- `sessions` remains the source of truth for active and historical online state.

After a voucher is redeemed, access decisions should use wallet/session state rather than trusting the voucher alone.

## Phase 2B Portal Sessions

Client portal state is tracked in PostgreSQL:

- `portal_sessions` stores the public browser/session ID, future captive portal query parameters, source, status, linked user, and linked voucher.
- `portal_events` records portal views, voucher submissions, success/failure events, and status views.
- `voucher_redemptions.source = CLIENT_PORTAL` identifies customer-facing portal redemption.

Portal sessions and events are integration context. Vouchers still credit wallets, and wallet/session records remain the source of truth after redemption.

## Phase 2C Omada Authorization Context

Omada captive portal data is integration context, not source of truth.

- `portal_sessions` stores normalized Omada redirect values, raw query parameters, access timestamps, and Omada authorization status.
- `omada_portal_authorizations` stores each Omada authorization attempt and sanitized request/response summaries.
- `captive_portal_settings` stores open SSID, portal URLs, selected Omada site, and one-AP test checklist progress.
- `captive_portal_test_logs` stores setup and automation test results.
- `mikrotik_routers` stores MikroTik gateway/API connection records for the MikroTik-first captive portal direction. Passwords are encrypted and router records are integration settings, not source-of-truth customer data.
- `portal_design_templates` stores the editable customer portal HTML/CSS template.

For Omada-sourced sessions, voucher redemption is only committed after Omada authorization succeeds. Wallets and sessions remain the source of truth after that redemption.

For the MikroTik direction, MikroTik will be the gateway/enforcement client. Vouchers, wallets, portal sessions, and accounting records remain the source of truth inside PostgreSQL.
