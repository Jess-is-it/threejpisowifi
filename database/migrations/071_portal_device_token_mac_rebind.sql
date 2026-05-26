ALTER TABLE portal_sessions
    ADD COLUMN IF NOT EXISTS device_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS device_token_created_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS device_token_last_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mac_rebind_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_mac_rebind_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS previous_client_macs JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE UNIQUE INDEX IF NOT EXISTS idx_portal_sessions_device_token_hash
    ON portal_sessions(device_token_hash)
    WHERE device_token_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_portal_sessions_access_window
    ON portal_sessions(status, access_expires_at);

CREATE TABLE IF NOT EXISTS portal_mac_rebind_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    source TEXT,
    old_client_mac TEXT,
    new_client_mac TEXT,
    old_client_ip INET,
    new_client_ip INET,
    remaining_seconds INTEGER,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED', 'SKIPPED')),
    message TEXT,
    authorization_summary JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_mac_rebind_events_session
    ON portal_mac_rebind_events(portal_session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_portal_mac_rebind_events_created_at
    ON portal_mac_rebind_events(created_at DESC);

ALTER TABLE portal_events DROP CONSTRAINT IF EXISTS portal_events_event_type_check;
ALTER TABLE portal_events
    ADD CONSTRAINT portal_events_event_type_check
    CHECK (event_type IN (
        'PORTAL_VIEW',
        'VOUCHER_SUBMITTED',
        'VOUCHER_REDEEM_SUCCESS',
        'VOUCHER_REDEEM_FAILED',
        'STATUS_VIEW',
        'MAC_REBIND_ATTEMPT',
        'MAC_REBIND_SUCCESS',
        'MAC_REBIND_FAILED',
        'MAC_REBIND_SKIPPED'
    ));
