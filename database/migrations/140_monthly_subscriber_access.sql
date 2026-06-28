CREATE TABLE IF NOT EXISTS monthly_subscriber_settings (
    id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id = true),
    integration_enabled BOOLEAN NOT NULL DEFAULT true,
    api_key TEXT NOT NULL DEFAULT 'threejmain-monthly',
    api_secret TEXT,
    rolling_authorization_seconds INTEGER NOT NULL DEFAULT 2592000,
    login_otp_ttl_seconds INTEGER NOT NULL DEFAULT 300,
    login_otp_cooldown_seconds INTEGER NOT NULL DEFAULT 60,
    source_system_label TEXT NOT NULL DEFAULT '3J Main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO monthly_subscriber_settings(id)
VALUES (true)
ON CONFLICT (id) DO NOTHING;

ALTER TABLE monthly_subscriber_settings
    DROP CONSTRAINT IF EXISTS monthly_subscriber_settings_authorization_positive,
    DROP CONSTRAINT IF EXISTS monthly_subscriber_settings_otp_ttl_positive,
    DROP CONSTRAINT IF EXISTS monthly_subscriber_settings_otp_cooldown_positive;

ALTER TABLE monthly_subscriber_settings
    ADD CONSTRAINT monthly_subscriber_settings_authorization_positive
        CHECK (rolling_authorization_seconds BETWEEN 300 AND 2592000),
    ADD CONSTRAINT monthly_subscriber_settings_otp_ttl_positive
        CHECK (login_otp_ttl_seconds BETWEEN 60 AND 1800),
    ADD CONSTRAINT monthly_subscriber_settings_otp_cooldown_positive
        CHECK (login_otp_cooldown_seconds BETWEEN 10 AND 600);

CREATE TABLE IF NOT EXISTS monthly_subscribers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_subscriber_id TEXT NOT NULL UNIQUE,
    account_number TEXT,
    service_account_number TEXT,
    customer_name TEXT NOT NULL,
    plan_name TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DISCONNECTED', 'INACTIVE')),
    source_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_monthly_subscribers_status
    ON monthly_subscribers(status);

CREATE INDEX IF NOT EXISTS idx_monthly_subscribers_customer_name
    ON monthly_subscribers(lower(customer_name));

CREATE TABLE IF NOT EXISTS monthly_subscriber_contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_id UUID NOT NULL REFERENCES monthly_subscribers(id) ON DELETE CASCADE,
    contact_number TEXT NOT NULL,
    normalized_contact TEXT NOT NULL UNIQUE,
    label TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'DISABLED', 'REVOKED')),
    bound_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    bound_portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    bound_device_token_hash TEXT,
    bound_client_mac TEXT,
    bound_client_ip INET,
    bound_user_agent TEXT,
    bound_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_monthly_subscriber_contacts_subscriber
    ON monthly_subscriber_contacts(subscriber_id);

CREATE INDEX IF NOT EXISTS idx_monthly_subscriber_contacts_status
    ON monthly_subscriber_contacts(status);

CREATE INDEX IF NOT EXISTS idx_monthly_subscriber_contacts_bound_user
    ON monthly_subscriber_contacts(bound_user_id);

CREATE TABLE IF NOT EXISTS monthly_subscriber_login_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contact_id UUID REFERENCES monthly_subscriber_contacts(id) ON DELETE CASCADE,
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    normalized_contact TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'FAILED')),
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_monthly_subscriber_login_challenges_contact
    ON monthly_subscriber_login_challenges(contact_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_monthly_subscriber_login_challenges_normalized
    ON monthly_subscriber_login_challenges(normalized_contact, created_at DESC);

CREATE TABLE IF NOT EXISTS monthly_subscriber_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_system TEXT NOT NULL DEFAULT '3J Main',
    request_id TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'SUCCESS'
        CHECK (status IN ('SUCCESS', 'FAILED', 'PARTIAL')),
    subscriber_count INTEGER NOT NULL DEFAULT 0,
    contact_count INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_monthly_subscriber_sync_logs_created
    ON monthly_subscriber_sync_logs(created_at DESC);

ALTER TABLE portal_sessions
    ADD COLUMN IF NOT EXISTS monthly_subscriber_contact_id UUID REFERENCES monthly_subscriber_contacts(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS monthly_subscriber_authorized_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS monthly_subscriber_status TEXT NOT NULL DEFAULT 'NONE'
        CHECK (monthly_subscriber_status IN ('NONE', 'ACTIVE', 'FAILED', 'REVOKED'));

CREATE INDEX IF NOT EXISTS idx_portal_sessions_monthly_contact
    ON portal_sessions(monthly_subscriber_contact_id);
