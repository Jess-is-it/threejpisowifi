CREATE TABLE IF NOT EXISTS locations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    location_name TEXT,
    address TEXT NOT NULL,
    municipality TEXT,
    barangay TEXT,
    province TEXT,
    region TEXT,
    latitude NUMERIC(10, 7),
    longitude NUMERIC(10, 7),
    geocode_source TEXT,
    raw_geocode JSONB,
    notes TEXT,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE site_deployments ADD COLUMN IF NOT EXISTS location_id UUID REFERENCES locations(id) ON DELETE SET NULL;
ALTER TABLE site_deployments ADD COLUMN IF NOT EXISTS municipality TEXT;
ALTER TABLE site_deployments ADD COLUMN IF NOT EXISTS barangay TEXT;
ALTER TABLE site_deployments ADD COLUMN IF NOT EXISTS latitude NUMERIC(10, 7);
ALTER TABLE site_deployments ADD COLUMN IF NOT EXISTS longitude NUMERIC(10, 7);

CREATE INDEX IF NOT EXISTS idx_locations_created_at ON locations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_locations_municipality_barangay ON locations(municipality, barangay);
CREATE INDEX IF NOT EXISTS idx_site_deployments_location_id ON site_deployments(location_id);
