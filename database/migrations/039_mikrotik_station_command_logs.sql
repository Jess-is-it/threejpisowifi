CREATE TABLE IF NOT EXISTS mikrotik_station_command_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    station_id UUID REFERENCES mikrotik_stations(id) ON DELETE CASCADE,
    router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    operation TEXT NOT NULL CHECK (operation IN ('CHECK', 'APPLY', 'REMOVE')),
    command_index INTEGER,
    command_label TEXT,
    command_preview TEXT,
    command_status TEXT NOT NULL,
    message TEXT,
    result_json JSONB,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_station_command_logs_station
    ON mikrotik_station_command_logs(station_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_station_command_logs_router
    ON mikrotik_station_command_logs(router_id, created_at DESC);
