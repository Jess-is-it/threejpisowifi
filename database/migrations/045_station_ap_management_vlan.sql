ALTER TABLE mikrotik_stations
    ADD COLUMN IF NOT EXISTS ap_management_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ap_management_vlan_id INTEGER CHECK (ap_management_vlan_id BETWEEN 1 AND 4094),
    ADD COLUMN IF NOT EXISTS ap_management_vlan_interface_name TEXT,
    ADD COLUMN IF NOT EXISTS ap_management_network_cidr TEXT,
    ADD COLUMN IF NOT EXISTS ap_management_gateway_ip TEXT,
    ADD COLUMN IF NOT EXISTS ap_management_pool_start_ip TEXT,
    ADD COLUMN IF NOT EXISTS ap_management_pool_end_ip TEXT,
    ADD COLUMN IF NOT EXISTS ap_management_pool_name TEXT,
    ADD COLUMN IF NOT EXISTS ap_management_dhcp_server_name TEXT,
    ADD COLUMN IF NOT EXISTS ap_management_dhcp_lease_time TEXT DEFAULT '1h',
    ADD COLUMN IF NOT EXISTS ap_management_dns_servers TEXT;

UPDATE mikrotik_stations
SET ap_management_dhcp_lease_time = COALESCE(NULLIF(btrim(ap_management_dhcp_lease_time), ''), '1h')
WHERE ap_management_dhcp_lease_time IS NULL OR btrim(ap_management_dhcp_lease_time) = '';
