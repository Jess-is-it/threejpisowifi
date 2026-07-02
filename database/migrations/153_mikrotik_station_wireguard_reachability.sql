ALTER TABLE mikrotik_stations
    ADD COLUMN IF NOT EXISTS gateway_mode TEXT NOT NULL DEFAULT 'CENTRAL_ROOT_GATEWAY'
        CHECK (gateway_mode IN ('CENTRAL_ROOT_GATEWAY', 'LOCAL_STATION_GATEWAY')),
    ADD COLUMN IF NOT EXISTS wireguard_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS wireguard_interface_name TEXT,
    ADD COLUMN IF NOT EXISTS wireguard_station_address TEXT,
    ADD COLUMN IF NOT EXISTS wireguard_station_public_key TEXT,
    ADD COLUMN IF NOT EXISTS wireguard_peer_public_key TEXT,
    ADD COLUMN IF NOT EXISTS wireguard_endpoint_host TEXT,
    ADD COLUMN IF NOT EXISTS wireguard_endpoint_port INTEGER CHECK (wireguard_endpoint_port IS NULL OR (wireguard_endpoint_port BETWEEN 1 AND 65535)),
    ADD COLUMN IF NOT EXISTS wireguard_allowed_addresses TEXT,
    ADD COLUMN IF NOT EXISTS wireguard_route_distance INTEGER CHECK (wireguard_route_distance IS NULL OR (wireguard_route_distance BETWEEN 1 AND 255)),
    ADD COLUMN IF NOT EXISTS wireguard_persistent_keepalive INTEGER CHECK (wireguard_persistent_keepalive IS NULL OR (wireguard_persistent_keepalive BETWEEN 0 AND 65535)),
    ADD COLUMN IF NOT EXISTS wireguard_hub_router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS wireguard_hub_interface_name TEXT,
    ADD COLUMN IF NOT EXISTS wireguard_hub_allowed_addresses TEXT;

UPDATE mikrotik_stations
SET gateway_mode = COALESCE(NULLIF(btrim(gateway_mode), ''), 'CENTRAL_ROOT_GATEWAY'),
    wireguard_interface_name = COALESCE(NULLIF(btrim(wireguard_interface_name), ''), 'WG-3J-' || COALESCE(NULLIF(btrim(station_code), ''), lower(regexp_replace(btrim(station_name), '[^a-zA-Z0-9]+', '-', 'g')))),
    wireguard_endpoint_port = COALESCE(wireguard_endpoint_port, 51820),
    wireguard_allowed_addresses = COALESCE(NULLIF(btrim(wireguard_allowed_addresses), ''), '192.168.50.0/24,10.250.0.1/32'),
    wireguard_route_distance = COALESCE(wireguard_route_distance, 200),
    wireguard_persistent_keepalive = COALESCE(wireguard_persistent_keepalive, 25)
WHERE status <> 'ARCHIVED';

CREATE INDEX IF NOT EXISTS idx_mikrotik_stations_wireguard_enabled
    ON mikrotik_stations(wireguard_enabled)
    WHERE status <> 'ARCHIVED';

CREATE INDEX IF NOT EXISTS idx_mikrotik_stations_wireguard_hub_router
    ON mikrotik_stations(wireguard_hub_router_id)
    WHERE wireguard_hub_router_id IS NOT NULL;
