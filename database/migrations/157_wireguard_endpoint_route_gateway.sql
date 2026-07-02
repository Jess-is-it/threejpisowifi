ALTER TABLE mikrotik_stations
    ADD COLUMN IF NOT EXISTS wireguard_endpoint_route_gateway TEXT;
