CREATE TABLE IF NOT EXISTS ap_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    omada_site_id TEXT NOT NULL,
    site_name TEXT,
    mac TEXT NOT NULL,
    normalized_mac TEXT NOT NULL,
    display_name TEXT NOT NULL,
    model TEXT,
    ip_address TEXT,
    firmware_version TEXT,
    serial_number TEXT,
    deployment_status TEXT NOT NULL DEFAULT 'ADOPTING'
        CHECK (deployment_status IN ('ADOPTING', 'CONNECTED', 'ADOPT_FAILED', 'DISCONNECTED', 'DELETED')),
    last_error TEXT,
    last_seen TIMESTAMPTZ,
    last_omada_status TEXT,
    raw_omada jsonb,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ap_deployments_site_mac ON ap_deployments(omada_site_id, normalized_mac);
CREATE INDEX IF NOT EXISTS idx_ap_deployments_status ON ap_deployments(deployment_status);
CREATE INDEX IF NOT EXISTS idx_ap_deployments_site ON ap_deployments(omada_site_id);
