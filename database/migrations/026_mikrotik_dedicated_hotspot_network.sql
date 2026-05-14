ALTER TABLE mikrotik_routers
    ADD COLUMN IF NOT EXISTS hotspot_client_network_cidr TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_gateway_ip TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_pool_start_ip TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_pool_end_ip TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_pool_name TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_dhcp_server_name TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_dhcp_lease_time TEXT NOT NULL DEFAULT '1h',
    ADD COLUMN IF NOT EXISTS hotspot_dns_servers TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_wan_interface TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_enable_nat BOOLEAN NOT NULL DEFAULT false;

UPDATE mikrotik_routers
SET hotspot_interface = NULL,
    hotspot_address_pool = NULL,
    configuration_step_status = configuration_step_status - 'prepare_hotspot_profile',
    updated_at = now()
WHERE configuration_step_status -> 'prepare_hotspot_profile' ->> 'status' = 'DETECTED';

