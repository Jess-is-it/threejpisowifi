# Database Source Of Truth

PostgreSQL remains the source of truth for 3JCentralPisowifi.

## Active Source-Of-Truth Records

- `admins`: admin users.
- `users`: portal/customer account records.
- `customer_bag_items`: purchased, store-approved, admin-granted, welcome-gift, voucher-claimed, and IPTV-capable bag items.
- `customer_bag_events`: activation, consumption, admin adjustment, and other WiFi Bag history.
- `iptv_accounts`, `iptv_provisioning_jobs`, and `iptv_login_tokens`: XUI account mapping, provisioning queue/history, and short-lived IPTV web login tokens.
- `product_categories`, `product_items`, and `product_category_item_assignments`: online WiFi/IPTV package catalog. Items are reusable catalog entries; category assignments decide which items appear in each portal category. The older direct `product_items.category_id` column is retained only for schema compatibility and should stay null for the active workflow.
- `physical_stores`, store owner tables, store items, and `store_purchase_requests`: physical-store sales and approvals.
- `sales`: online and physical-store sales reporting.
- `vouchers`: optional code inventory for events, refunds, and gifts.
- `voucher_redemptions`: voucher claim attempts/results.
- `portal_sessions`: browser/device portal context.
- `portal_events`: portal views, purchase activity, voucher submissions, failures, and status checks.
- `portal_mac_rebind_events`: random/private-MAC device-token reauthorization events.
- `omada_portal_authorizations`: Omada client authorization attempts.
- `captive_portal_settings`: portal URLs, Omada captive portal settings, notification switches/templates, welcome SMS, portal design controls, profile gift controls, and customer-facing text.
- `mikrotik_routers`: RouterOS API connection records for station transport planning.
- `mikrotik_preflight_scans`: read-only scan snapshots used to validate VLANs/subnets/pools/DHCP/routing risks.
- `mikrotik_stations` and related station tables: reviewed station VLAN/DHCP/NAT/trunk transport plans.
- AP deployment and Omada site/AP configuration tables: local AP/site/SSID configuration state.
- `omada_controller_settings`, `omada_api_settings`, `omada_install_logs`, and `omada_automation_logs`: Omada install/manage/API state.
- Smart A2P settings/log tables: SMS configuration, credit tracking, and message delivery history.
- `audit_logs`: operator/system audit trail.

## WiFi Bag Rules

The WiFi Bag is the active access ledger.

- Paid PayMongo products create bag items after payment confirmation.
- IPTV-capable PayMongo products snapshot `product_kind` into `payment_orders` and `customer_bag_items`. `IPTV`-only bag items queue XUI provisioning, not hotspot internet time.
- Physical Store approvals create bag items after the store owner approves a request, QR, or code.
- Voucher claims create bag items instead of wallet credit.
- Admin time adjustments are recorded in `customer_bag_events`.
- Omada authorization is attempted when an active bag item/session should grant network access.

Do not reintroduce `wallets`, `transactions`, or Wallet / Manual Top-Up behavior.

## Portal Session Rules

Omada captive portal data is integration context, not the database of record.

- `portal_sessions` stores Omada redirect values, raw query params, authorization status, and access timestamps.
- `portal_sessions.device_token_hash` stores only a hashed browser device-session token used for random/private-MAC rebinds.
- `portal_events` stores user-visible portal activity and troubleshooting context.
- `omada_portal_authorizations` stores sanitized Omada API request/response summaries.
- `portal_mac_rebind_events` records old/new MAC, remaining time, status, and sanitized authorization summary when token-based MAC rebind is attempted.

## MikroTik Rules

MikroTik is not the source of truth for customer access time.

MikroTik tables store:

- Router API credentials/settings.
- Read-only preflight scan data.
- Station transport plans.
- AP management transport plans.
- RouterOS command history for reviewed transport pushes/removals.

MikroTik HotSpot enforcement, managed `login.html`, HotSpot client authorization, and Office AP Path transport are retired from the active workflow.

## Retired Tables

Migration `117_cleanup_retired_wallet_ai_radius_hotspot.sql` drops retired Wallet, RADIUS/NAS, AI/OpenAI planning, MikroTik HotSpot sync/authorization, Office AP Path, Omada RADIUS lab, and legacy portal template tables.

The legacy `sessions` table is temporarily retained only as a Customer Devices fallback/history source. New access features should use `portal_sessions`, `customer_bag_items`, and `customer_bag_events`.
