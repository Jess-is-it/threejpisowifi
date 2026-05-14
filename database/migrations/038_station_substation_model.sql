ALTER TABLE mikrotik_stations
    ADD COLUMN IF NOT EXISTS station_code TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_dns_name TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_server_name TEXT,
    ADD COLUMN IF NOT EXISTS portal_url TEXT;

UPDATE mikrotik_stations
SET station_code = lower(regexp_replace(btrim(station_name), '[^a-zA-Z0-9]+', '-', 'g'))
WHERE station_code IS NULL OR btrim(station_code) = '';

CREATE UNIQUE INDEX IF NOT EXISTS uq_mikrotik_stations_active_station_code
    ON mikrotik_stations (lower(btrim(station_code)))
    WHERE status <> 'ARCHIVED' AND station_code IS NOT NULL AND btrim(station_code) <> '';

CREATE UNIQUE INDEX IF NOT EXISTS uq_mikrotik_stations_active_vlan
    ON mikrotik_stations (vlan_id)
    WHERE status <> 'ARCHIVED';

CREATE UNIQUE INDEX IF NOT EXISTS uq_mikrotik_stations_active_client_network
    ON mikrotik_stations (lower(btrim(client_network_cidr)))
    WHERE status <> 'ARCHIVED';
