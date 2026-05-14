CREATE TABLE IF NOT EXISTS mikrotik_stations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    station_name TEXT NOT NULL,
    description TEXT,
    vlan_id INTEGER NOT NULL CHECK (vlan_id BETWEEN 1 AND 4094),
    vlan_interface_name TEXT,
    client_network_cidr TEXT NOT NULL,
    gateway_ip TEXT NOT NULL,
    pool_start_ip TEXT NOT NULL,
    pool_end_ip TEXT NOT NULL,
    pool_name TEXT,
    dns_servers TEXT,
    local_interface_list TEXT NOT NULL DEFAULT 'LOCAL',
    status TEXT NOT NULL DEFAULT 'DRAFT'
        CHECK (status IN ('DRAFT', 'READY_FOR_REVIEW', 'ACTIVE', 'ARCHIVED')),
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mikrotik_station_routers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    station_id UUID NOT NULL REFERENCES mikrotik_stations(id) ON DELETE CASCADE,
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE RESTRICT,
    sequence_order INTEGER NOT NULL,
    station_role TEXT NOT NULL
        CHECK (station_role IN ('ROOT_GATEWAY', 'TRUNK_HELPER')),
    bridge_name TEXT,
    tagged_ports TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (station_id, router_id),
    UNIQUE (station_id, sequence_order)
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_stations_status
    ON mikrotik_stations(status);

CREATE INDEX IF NOT EXISTS idx_mikrotik_station_routers_station
    ON mikrotik_station_routers(station_id, sequence_order);

CREATE INDEX IF NOT EXISTS idx_mikrotik_station_routers_router
    ON mikrotik_station_routers(router_id);
