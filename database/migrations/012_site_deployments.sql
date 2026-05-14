CREATE TABLE IF NOT EXISTS site_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_name TEXT NOT NULL,
    location TEXT,
    address TEXT,
    contact_name TEXT,
    contact_phone TEXT,
    omada_site_id TEXT,
    deployment_status TEXT NOT NULL DEFAULT 'PLANNED' CHECK (deployment_status IN ('PLANNED', 'INSTALLING', 'ACTIVE', 'INACTIVE', 'MAINTENANCE')),
    notes TEXT,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_site_deployments_status ON site_deployments(deployment_status);
CREATE INDEX IF NOT EXISTS idx_site_deployments_created_at ON site_deployments(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_site_deployments_site_name_lower ON site_deployments(lower(site_name));
