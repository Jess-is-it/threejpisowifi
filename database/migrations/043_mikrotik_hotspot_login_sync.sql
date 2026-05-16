CREATE TABLE IF NOT EXISTS mikrotik_hotspot_login_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    station_id UUID REFERENCES mikrotik_stations(id) ON DELETE CASCADE,
    router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    file_path TEXT NOT NULL,
    content_hash TEXT,
    sync_status TEXT NOT NULL CHECK (sync_status IN ('SUCCESS', 'FAILED', 'MISSING', 'OUTDATED', 'DETECTED', 'NOT_READY')),
    message TEXT,
    result_json JSONB,
    synced_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_hotspot_login_sync_logs_station
    ON mikrotik_hotspot_login_sync_logs(station_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_hotspot_login_sync_logs_router
    ON mikrotik_hotspot_login_sync_logs(router_id, created_at DESC);
