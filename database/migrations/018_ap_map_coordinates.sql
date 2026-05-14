ALTER TABLE ap_deployments
    ADD COLUMN IF NOT EXISTS map_latitude DOUBLE PRECISION
        CHECK (map_latitude IS NULL OR (map_latitude BETWEEN -90 AND 90)),
    ADD COLUMN IF NOT EXISTS map_longitude DOUBLE PRECISION
        CHECK (map_longitude IS NULL OR (map_longitude BETWEEN -180 AND 180)),
    ADD COLUMN IF NOT EXISTS map_source TEXT,
    ADD COLUMN IF NOT EXISTS mapped_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS map_updated_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_ap_deployments_map_coordinates
    ON ap_deployments(map_latitude, map_longitude)
    WHERE map_latitude IS NOT NULL AND map_longitude IS NOT NULL;
