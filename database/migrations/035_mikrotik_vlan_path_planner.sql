CREATE TABLE IF NOT EXISTS mikrotik_vlan_path_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE CASCADE,
    hotspot_gateway_router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    gateway_parent_interface TEXT,
    next_hop_type TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK (next_hop_type IN ('CRS', 'OLT', 'SWITCH', 'DIRECT_AP', 'UNKNOWN')),
    crs_involved BOOLEAN NOT NULL DEFAULT false,
    crs_router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    crs_port_to_gateway TEXT,
    crs_ports_to_olt_ap TEXT,
    olts_involved BOOLEAN NOT NULL DEFAULT false,
    olt_notes TEXT,
    olt_vlan_behavior TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK (olt_vlan_behavior IN ('TRANSPARENT', 'TRANSLATED', 'UNKNOWN')),
    ap_vlan_mode TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK (ap_vlan_mode IN ('TAGGED', 'UNTAGGED', 'UNKNOWN')),
    ssid_vlan_id INTEGER,
    confirmation_status TEXT NOT NULL DEFAULT 'DRAFT'
        CHECK (confirmation_status IN ('DRAFT', 'NEEDS_REVIEW', 'CONFIRMED')),
    confirmed_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (router_id)
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_vlan_path_plans_router
    ON mikrotik_vlan_path_plans(router_id);

CREATE INDEX IF NOT EXISTS idx_mikrotik_vlan_path_plans_crs_router
    ON mikrotik_vlan_path_plans(crs_router_id);
