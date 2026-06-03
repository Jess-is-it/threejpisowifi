CREATE TABLE IF NOT EXISTS physical_stores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_name TEXT NOT NULL,
    description TEXT,
    image_url TEXT,
    address TEXT,
    municipality TEXT,
    barangay TEXT,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    contact_name TEXT,
    contact_phone TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    notes TEXT,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_stores_status_check'
    ) THEN
        ALTER TABLE physical_stores
            ADD CONSTRAINT physical_stores_status_check CHECK (status IN ('ACTIVE', 'DISABLED'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS physical_store_sites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_id UUID NOT NULL REFERENCES physical_stores(id) ON DELETE CASCADE,
    site_deployment_id UUID NOT NULL REFERENCES site_deployments(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(store_id, site_deployment_id)
);

CREATE INDEX IF NOT EXISTS idx_physical_stores_status_name
    ON physical_stores(status, lower(store_name));

CREATE INDEX IF NOT EXISTS idx_physical_store_sites_store_id
    ON physical_store_sites(store_id);

CREATE INDEX IF NOT EXISTS idx_physical_store_sites_site_id
    ON physical_store_sites(site_deployment_id);
