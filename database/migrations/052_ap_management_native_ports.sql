ALTER TABLE mikrotik_ap_management_routers
    ADD COLUMN IF NOT EXISTS untagged_ports TEXT;
