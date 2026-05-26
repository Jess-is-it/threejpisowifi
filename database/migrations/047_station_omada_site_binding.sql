ALTER TABLE mikrotik_stations
    ADD COLUMN IF NOT EXISTS omada_site_id TEXT,
    ADD COLUMN IF NOT EXISTS omada_site_name TEXT,
    ADD COLUMN IF NOT EXISTS omada_site_vlan_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS omada_site_bound_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS omada_site_bound_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_mikrotik_stations_omada_site_id
    ON mikrotik_stations(omada_site_id);
