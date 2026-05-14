ALTER TABLE users ADD COLUMN IF NOT EXISTS source TEXT;

CREATE TABLE IF NOT EXISTS portal_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_session_id TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
    client_mac TEXT,
    client_ip INET,
    ap_mac TEXT,
    ssid TEXT,
    site TEXT,
    gateway TEXT,
    nas_id TEXT,
    redirect_url TEXT,
    user_agent TEXT,
    source TEXT NOT NULL DEFAULT 'MANUAL_TEST' CHECK (source IN ('MANUAL_TEST', 'OMADA', 'MIKROTIK', 'UNKNOWN')),
    status TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'VOUCHER_REDEEMED', 'ACCESS_PENDING', 'ACCESS_GRANTED', 'ACCESS_DENIED', 'EXPIRED')),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS portal_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('PORTAL_VIEW', 'VOUCHER_SUBMITTED', 'VOUCHER_REDEEM_SUCCESS', 'VOUCHER_REDEEM_FAILED', 'STATUS_VIEW')),
    voucher_code_masked TEXT,
    message TEXT,
    ip_address INET,
    user_agent TEXT,
    raw_context JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_sessions_public_session_id ON portal_sessions(public_session_id);
CREATE INDEX IF NOT EXISTS idx_portal_sessions_user_id ON portal_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_portal_sessions_status ON portal_sessions(status);
CREATE INDEX IF NOT EXISTS idx_portal_events_created_at ON portal_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_portal_events_session ON portal_events(portal_session_id, created_at DESC);

UPDATE app_settings
SET value = jsonb_set(
    value,
    '{branding}',
    COALESCE(value->'branding', '{}'::jsonb) || '{
      "portal_title": "3J WiFi",
      "portal_subtitle": "Enter your voucher to connect",
      "portal_welcome_message": "Welcome to 3J WiFi. Please enter your voucher code to start using the internet.",
      "portal_support_text": "Need a voucher? Ask the nearest vendo/operator.",
      "portal_terms_note": "Use of this WiFi service is subject to local operator rules.",
      "portal_show_powered_by": true
    }'::jsonb
)
WHERE key = 'system';
