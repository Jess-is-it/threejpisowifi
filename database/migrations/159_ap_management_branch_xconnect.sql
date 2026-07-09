ALTER TABLE mikrotik_ap_management_routers
    ADD COLUMN IF NOT EXISTS ap_path_bridge_name TEXT;
