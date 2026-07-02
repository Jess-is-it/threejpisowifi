ALTER TABLE mikrotik_station_routers
    ADD COLUMN IF NOT EXISTS transport_mode TEXT NOT NULL DEFAULT 'BRIDGE_TRUNK',
    ADD COLUMN IF NOT EXISTS handoff_bridge_name TEXT,
    ADD COLUMN IF NOT EXISTS handoff_tagged_ports TEXT;

UPDATE mikrotik_station_routers
SET transport_mode = 'BRIDGE_TRUNK'
WHERE transport_mode IS NULL OR btrim(transport_mode) = '';
