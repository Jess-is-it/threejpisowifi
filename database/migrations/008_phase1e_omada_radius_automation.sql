CREATE TABLE IF NOT EXISTS omada_api_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    controller_host TEXT NOT NULL DEFAULT '192.168.50.71',
    https_port INTEGER NOT NULL DEFAULT 8043,
    api_base_url TEXT NOT NULL DEFAULT 'https://192.168.50.71:8043',
    verify_tls BOOLEAN NOT NULL DEFAULT false,
    username TEXT,
    password_encrypted TEXT,
    controller_id TEXT,
    selected_site_id TEXT,
    selected_site_name TEXT,
    last_login_success_at TIMESTAMPTZ,
    last_login_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS omada_radius_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    radius_server_ip TEXT NOT NULL DEFAULT '192.168.50.70',
    auth_port INTEGER NOT NULL,
    accounting_port INTEGER NOT NULL,
    shared_secret_encrypted TEXT NOT NULL,
    accounting_enabled BOOLEAN NOT NULL DEFAULT true,
    interim_update_seconds INTEGER NOT NULL DEFAULT 300,
    omada_profile_id TEXT,
    omada_site_id TEXT,
    status TEXT NOT NULL DEFAULT 'DRAFT',
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (environment IN ('STAGING', 'PRODUCTION')),
    CHECK (status IN ('DRAFT', 'CREATED', 'FAILED'))
);

CREATE TABLE IF NOT EXISTS omada_test_ssids (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment TEXT NOT NULL,
    ssid_name TEXT NOT NULL DEFAULT '3J-Test-WiFi',
    security_type TEXT NOT NULL DEFAULT 'WPA2-Enterprise',
    omada_wlan_id TEXT,
    omada_site_id TEXT,
    radius_profile_id UUID REFERENCES omada_radius_profiles(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT',
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (environment IN ('STAGING', 'PRODUCTION')),
    CHECK (status IN ('DRAFT', 'CREATED', 'FAILED'))
);

CREATE TABLE IF NOT EXISTS omada_automation_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    request_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (action IN ('TEST_API_LOGIN', 'DETECT_SITES', 'CREATE_RADIUS_PROFILE', 'CREATE_TEST_SSID', 'CREATE_MATCHING_NAS')),
    CHECK (status IN ('SUCCESS', 'FAILED', 'WARNING'))
);

CREATE INDEX IF NOT EXISTS idx_omada_automation_logs_created_at ON omada_automation_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_omada_radius_profiles_environment ON omada_radius_profiles(environment, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_omada_test_ssids_environment ON omada_test_ssids(environment, created_at DESC);

INSERT INTO omada_api_settings (controller_host, https_port, api_base_url, verify_tls)
SELECT '192.168.50.71', 8043, 'https://192.168.50.71:8043', false
WHERE NOT EXISTS (SELECT 1 FROM omada_api_settings);
