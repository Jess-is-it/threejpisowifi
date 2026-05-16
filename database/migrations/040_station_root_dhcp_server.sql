ALTER TABLE mikrotik_stations
    ADD COLUMN IF NOT EXISTS dhcp_server_name TEXT,
    ADD COLUMN IF NOT EXISTS dhcp_lease_time TEXT NOT NULL DEFAULT '1h',
    ADD COLUMN IF NOT EXISTS create_dhcp_server BOOLEAN NOT NULL DEFAULT TRUE;

UPDATE mikrotik_stations
SET dhcp_server_name = COALESCE(NULLIF(btrim(dhcp_server_name), ''), 'DHCP-3J-HOTSPOT-V' || vlan_id::TEXT),
    dhcp_lease_time = COALESCE(NULLIF(btrim(dhcp_lease_time), ''), '1h'),
    create_dhcp_server = COALESCE(create_dhcp_server, TRUE);
