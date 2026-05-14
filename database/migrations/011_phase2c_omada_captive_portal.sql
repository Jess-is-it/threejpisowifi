ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS gateway_mac TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS vlan_id TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS raw_query_params JSONB;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_site_id TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_site_name TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_client_mac TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_ap_mac TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_gateway_mac TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_token_encrypted TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_redirect_url TEXT;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS access_granted_at TIMESTAMPTZ;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS access_expires_at TIMESTAMPTZ;
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_authorization_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED';
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS omada_authorization_error TEXT;

CREATE TABLE IF NOT EXISTS omada_portal_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    client_mac TEXT,
    ap_mac TEXT,
    gateway_mac TEXT,
    site_name TEXT,
    site_id TEXT,
    ssid TEXT,
    authorization_duration_seconds INTEGER,
    access_expires_at TIMESTAMPTZ,
    omada_request_summary JSONB,
    omada_response_summary JSONB,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED')),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS captive_portal_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portal_mode TEXT NOT NULL DEFAULT 'OMADA' CHECK (portal_mode IN ('OMADA', 'MIKROTIK', 'DISABLED')),
    open_ssid_name TEXT NOT NULL DEFAULT '3J-FreeWiFi',
    portal_url_staging TEXT NOT NULL DEFAULT 'http://192.168.50.70:8080/portal',
    portal_url_production TEXT NOT NULL DEFAULT 'http://192.168.50.70/portal',
    default_access_duration_seconds INTEGER,
    post_login_redirect_url TEXT,
    selected_omada_site_id TEXT,
    selected_omada_site_name TEXT,
    test_checklist_progress JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED' CHECK (status IN ('NOT_CONFIGURED', 'READY_FOR_TEST', 'TESTING', 'ACTIVE')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS captive_portal_test_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_omada_portal_authorizations_session ON omada_portal_authorizations(portal_session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_omada_portal_authorizations_status ON omada_portal_authorizations(status);
CREATE INDEX IF NOT EXISTS idx_captive_portal_test_logs_created_at ON captive_portal_test_logs(created_at DESC);

INSERT INTO captive_portal_settings(portal_mode, status)
SELECT 'OMADA', 'READY_FOR_TEST'
WHERE NOT EXISTS (SELECT 1 FROM captive_portal_settings);
