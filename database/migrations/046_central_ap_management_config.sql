CREATE TABLE IF NOT EXISTS mikrotik_ap_management_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_name TEXT NOT NULL DEFAULT 'Central AP Management',
    vlan_id INTEGER NOT NULL CHECK (vlan_id BETWEEN 1 AND 4094),
    vlan_interface_name TEXT,
    network_cidr TEXT NOT NULL,
    gateway_ip TEXT NOT NULL,
    pool_start_ip TEXT NOT NULL,
    pool_end_ip TEXT NOT NULL,
    pool_name TEXT,
    dhcp_server_name TEXT,
    dhcp_lease_time TEXT NOT NULL DEFAULT '1h',
    dns_servers TEXT,
    local_interface_list TEXT NOT NULL DEFAULT 'LOCAL',
    status TEXT NOT NULL DEFAULT 'READY_FOR_REVIEW'
        CHECK (status IN ('DRAFT', 'READY_FOR_REVIEW', 'ACTIVE', 'ARCHIVED')),
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mikrotik_ap_management_routers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL REFERENCES mikrotik_ap_management_configs(id) ON DELETE CASCADE,
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE RESTRICT,
    sequence_order INTEGER NOT NULL,
    router_role TEXT NOT NULL
        CHECK (router_role IN ('ROOT_GATEWAY', 'TRUNK_HELPER')),
    bridge_name TEXT,
    tagged_ports TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (config_id, router_id),
    UNIQUE (config_id, sequence_order)
);

CREATE TABLE IF NOT EXISTS mikrotik_ap_management_command_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID REFERENCES mikrotik_ap_management_configs(id) ON DELETE CASCADE,
    router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    command_index INTEGER,
    command_label TEXT,
    command_preview TEXT,
    status TEXT NOT NULL,
    message TEXT,
    result_json JSONB,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_ap_management_configs_status
    ON mikrotik_ap_management_configs(status);

CREATE INDEX IF NOT EXISTS idx_mikrotik_ap_management_routers_config
    ON mikrotik_ap_management_routers(config_id, sequence_order);

CREATE INDEX IF NOT EXISTS idx_mikrotik_ap_management_command_logs_config
    ON mikrotik_ap_management_command_logs(config_id, created_at DESC);

-- AP management is now centralized, not part of station-specific plans.
UPDATE mikrotik_stations
SET ap_management_enabled = FALSE
WHERE ap_management_enabled = TRUE;
