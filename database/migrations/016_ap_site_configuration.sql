ALTER TABLE site_deployments
    ADD COLUMN IF NOT EXISTS vlan_tag INTEGER CHECK (vlan_tag IS NULL OR (vlan_tag BETWEEN 1 AND 4094));

ALTER TABLE ap_deployments
    ADD COLUMN IF NOT EXISTS configuration_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (configuration_status IN ('NOT_CONFIGURED', 'PENDING', 'APPLYING', 'APPLIED', 'FAILED')),
    ADD COLUMN IF NOT EXISTS configuration_error TEXT,
    ADD COLUMN IF NOT EXISTS configured_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS ap_deployment_configuration (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    auto_apply_enabled BOOLEAN NOT NULL DEFAULT true,
    device_account_username TEXT,
    device_account_password_encrypted TEXT,
    use_same_ssid BOOLEAN NOT NULL DEFAULT true,
    same_ssid_name TEXT NOT NULL DEFAULT '3J-FreeWiFi',
    ssid_2g TEXT NOT NULL DEFAULT '3J-FreeWiFi-2G',
    ssid_5g TEXT NOT NULL DEFAULT '3J-FreeWiFi-5G',
    band_steering_enabled BOOLEAN NOT NULL DEFAULT true,
    security_mode TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (security_mode IN ('OPEN', 'WPA2_PSK', 'WPA_WPA2_PSK')),
    security_password_encrypted TEXT,
    updated_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ap_deployment_configuration(id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS ap_configuration_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ap_deployment_id UUID REFERENCES ap_deployments(id) ON DELETE SET NULL,
    omada_site_id TEXT,
    site_name TEXT,
    ap_mac TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'FAILED', 'SKIPPED')),
    message TEXT,
    request_summary jsonb,
    response_summary jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ap_configuration_logs_ap ON ap_configuration_logs(ap_deployment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ap_configuration_logs_site ON ap_configuration_logs(omada_site_id, created_at DESC);
