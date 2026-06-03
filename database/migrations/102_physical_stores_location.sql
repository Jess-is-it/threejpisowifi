ALTER TABLE physical_stores
    ADD COLUMN IF NOT EXISTS location_id UUID REFERENCES locations(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_physical_stores_location_id
    ON physical_stores(location_id);
