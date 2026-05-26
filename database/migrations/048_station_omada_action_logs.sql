ALTER TABLE captive_portal_test_logs
    ADD COLUMN IF NOT EXISTS station_id UUID REFERENCES mikrotik_stations(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS omada_site_id TEXT,
    ADD COLUMN IF NOT EXISTS omada_site_name TEXT,
    ADD COLUMN IF NOT EXISTS ssid_name TEXT;

CREATE INDEX IF NOT EXISTS idx_captive_portal_test_logs_station
    ON captive_portal_test_logs(station_id, created_at DESC);
