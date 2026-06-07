-- Cleanup retired features after the Omada Captive Portal + WiFi Bag pivot.
--
-- Current active access flow:
--   Product Items / Physical Stores / Vouchers -> Customer WiFi Bag
--   -> Omada Captive Portal authorization.
--
-- The old Wallet, FreeRADIUS/NAS lab tooling, AI Network Assistant planning
-- tables, MikroTik login.html sync, MikroTik HotSpot authorization, and Office
-- AP Path transport experiments are no longer part of the active product.
--
-- Intentionally retained:
--   sessions
-- Customer Devices still uses it as a local fallback/history source.

ALTER TABLE voucher_redemptions
    DROP COLUMN IF EXISTS wallet_transaction_id;

DELETE FROM app_settings
WHERE key = 'openai';

DROP TABLE IF EXISTS mikrotik_ai_messages CASCADE;
DROP TABLE IF EXISTS mikrotik_ai_conversations CASCADE;
DROP TABLE IF EXISTS mikrotik_ai_smoke_tests CASCADE;
DROP TABLE IF EXISTS mikrotik_ai_planning_suggestions CASCADE;
DROP TABLE IF EXISTS mikrotik_planning_derivations CASCADE;
DROP TABLE IF EXISTS mikrotik_vlan_path_plans CASCADE;
DROP TABLE IF EXISTS mikrotik_draft_deployment_plans CASCADE;
DROP TABLE IF EXISTS mikrotik_deployment_questions CASCADE;
DROP TABLE IF EXISTS mikrotik_pilot_selection CASCADE;

DROP TABLE IF EXISTS mikrotik_hotspot_login_sync_logs CASCADE;
DROP TABLE IF EXISTS mikrotik_portal_authorizations CASCADE;
DROP TABLE IF EXISTS mikrotik_office_ap_path_command_logs CASCADE;
DROP TABLE IF EXISTS mikrotik_office_ap_path_routers CASCADE;
DROP TABLE IF EXISTS mikrotik_office_ap_path_configs CASCADE;

DROP TABLE IF EXISTS omada_test_ssids CASCADE;
DROP TABLE IF EXISTS omada_radius_profiles CASCADE;

DROP TABLE IF EXISTS radius_auth_logs CASCADE;
DROP TABLE IF EXISTS radius_accounting_logs CASCADE;
DROP TABLE IF EXISTS nas_clients CASCADE;
DROP TABLE IF EXISTS radcheck CASCADE;
DROP TABLE IF EXISTS radreply CASCADE;
DROP TABLE IF EXISTS radacct CASCADE;
DROP TABLE IF EXISTS radusergroup CASCADE;
DROP TABLE IF EXISTS radgroupcheck CASCADE;
DROP TABLE IF EXISTS radgroupreply CASCADE;
DROP TABLE IF EXISTS nas CASCADE;

DROP TABLE IF EXISTS portal_design_templates CASCADE;

DROP TABLE IF EXISTS transactions CASCADE;
DROP TABLE IF EXISTS wallets CASCADE;
