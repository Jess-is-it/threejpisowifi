CREATE TABLE IF NOT EXISTS ap_managed_ssids (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    omada_site_id TEXT NOT NULL,
    wlan_id TEXT,
    ssid_id TEXT,
    ssid_name TEXT NOT NULL,
    band INTEGER,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'REMOVED', 'REMOVE_FAILED')),
    last_error TEXT,
    response_summary jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ap_managed_ssids_site_name
    ON ap_managed_ssids(omada_site_id, ssid_name);

CREATE INDEX IF NOT EXISTS idx_ap_managed_ssids_site_status
    ON ap_managed_ssids(omada_site_id, status);
