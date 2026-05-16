ALTER TABLE portal_sessions
    ADD COLUMN IF NOT EXISTS mikrotik_client_mac TEXT,
    ADD COLUMN IF NOT EXISTS mikrotik_client_ip INET,
    ADD COLUMN IF NOT EXISTS mikrotik_server_name TEXT,
    ADD COLUMN IF NOT EXISTS mikrotik_link_login TEXT,
    ADD COLUMN IF NOT EXISTS mikrotik_link_login_only TEXT,
    ADD COLUMN IF NOT EXISTS mikrotik_link_orig TEXT,
    ADD COLUMN IF NOT EXISTS mikrotik_chap_id TEXT,
    ADD COLUMN IF NOT EXISTS mikrotik_chap_challenge TEXT,
    ADD COLUMN IF NOT EXISTS mikrotik_authorization_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
    ADD COLUMN IF NOT EXISTS mikrotik_authorization_error TEXT;

CREATE TABLE IF NOT EXISTS mikrotik_portal_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    station_id UUID REFERENCES mikrotik_stations(id) ON DELETE SET NULL,
    router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    client_mac TEXT,
    client_ip INET,
    hotspot_server_name TEXT,
    authorization_duration_seconds INTEGER,
    access_expires_at TIMESTAMPTZ,
    mikrotik_request_summary JSONB,
    mikrotik_response_summary JSONB,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED')),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_portal_authorizations_session
    ON mikrotik_portal_authorizations(portal_session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_portal_authorizations_status
    ON mikrotik_portal_authorizations(status);

CREATE INDEX IF NOT EXISTS idx_mikrotik_portal_authorizations_station
    ON mikrotik_portal_authorizations(station_id, created_at DESC);
