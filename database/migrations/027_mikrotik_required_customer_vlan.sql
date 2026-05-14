ALTER TABLE mikrotik_routers
    ADD COLUMN IF NOT EXISTS hotspot_vlan_id INTEGER CHECK (hotspot_vlan_id IS NULL OR (hotspot_vlan_id BETWEEN 1 AND 4094)),
    ADD COLUMN IF NOT EXISTS hotspot_vlan_parent_interface TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_vlan_interface_name TEXT;

CREATE INDEX IF NOT EXISTS idx_mikrotik_routers_hotspot_vlan_id
    ON mikrotik_routers(hotspot_vlan_id);
