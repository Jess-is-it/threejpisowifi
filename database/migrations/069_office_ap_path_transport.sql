CREATE TABLE IF NOT EXISTS mikrotik_office_ap_path_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_name TEXT NOT NULL DEFAULT 'Office AP Path',
    office_bridge_name TEXT NOT NULL,
    transport_vlan_id INTEGER NOT NULL CHECK (transport_vlan_id BETWEEN 1 AND 4094),
    transport_vlan_interface_name TEXT,
    status TEXT NOT NULL DEFAULT 'READY_FOR_REVIEW'
        CHECK (status IN ('DRAFT', 'READY_FOR_REVIEW', 'ACTIVE', 'ARCHIVED')),
    pending_cleanup_plan_json JSONB,
    pending_cleanup_reason TEXT,
    pending_cleanup_created_at TIMESTAMPTZ,
    pending_cleanup_resolved_at TIMESTAMPTZ,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mikrotik_office_ap_path_routers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL REFERENCES mikrotik_office_ap_path_configs(id) ON DELETE CASCADE,
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

CREATE TABLE IF NOT EXISTS mikrotik_office_ap_path_command_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID REFERENCES mikrotik_office_ap_path_configs(id) ON DELETE CASCADE,
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

CREATE INDEX IF NOT EXISTS idx_mikrotik_office_ap_path_configs_status
    ON mikrotik_office_ap_path_configs(status);

CREATE INDEX IF NOT EXISTS idx_mikrotik_office_ap_path_routers_config
    ON mikrotik_office_ap_path_routers(config_id, sequence_order);

CREATE INDEX IF NOT EXISTS idx_mikrotik_office_ap_path_command_logs_config
    ON mikrotik_office_ap_path_command_logs(config_id, created_at DESC);
