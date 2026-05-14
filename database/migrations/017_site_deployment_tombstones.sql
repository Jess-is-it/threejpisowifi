CREATE TABLE IF NOT EXISTS site_deployment_tombstones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    omada_site_id TEXT,
    site_name TEXT,
    deleted_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    omada_delete_attempted BOOLEAN NOT NULL DEFAULT false,
    omada_deleted BOOLEAN NOT NULL DEFAULT false,
    omada_delete_error TEXT,
    omada_response_summary JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_site_deployment_tombstones_omada_site_id
    ON site_deployment_tombstones(omada_site_id)
    WHERE omada_site_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_site_deployment_tombstones_site_name_lower
    ON site_deployment_tombstones(lower(site_name))
    WHERE site_name IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_site_deployment_tombstones_created_at
    ON site_deployment_tombstones(created_at DESC);
