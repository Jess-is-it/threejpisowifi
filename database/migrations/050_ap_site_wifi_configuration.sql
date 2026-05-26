ALTER TABLE ap_deployment_configuration
    ADD COLUMN IF NOT EXISTS ssid_scope TEXT NOT NULL DEFAULT 'GLOBAL'
        CHECK (ssid_scope IN ('GLOBAL', 'PER_SITE'));

CREATE TABLE IF NOT EXISTS ap_site_wifi_configuration (
    site_id UUID PRIMARY KEY REFERENCES site_deployments(id) ON DELETE CASCADE,
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

CREATE INDEX IF NOT EXISTS idx_ap_site_wifi_configuration_updated_at
    ON ap_site_wifi_configuration(updated_at DESC);
