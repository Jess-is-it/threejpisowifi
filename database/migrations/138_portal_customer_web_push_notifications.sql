CREATE TABLE IF NOT EXISTS portal_customer_push_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    profile_id UUID REFERENCES portal_customer_profiles(id) ON DELETE CASCADE,
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    endpoint_hash TEXT NOT NULL UNIQUE,
    subscription_json JSONB NOT NULL,
    device_token_hash TEXT,
    user_agent TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_sent_at TIMESTAMPTZ,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'portal_customer_push_subscriptions_status_check'
    ) THEN
        ALTER TABLE portal_customer_push_subscriptions
            ADD CONSTRAINT portal_customer_push_subscriptions_status_check
            CHECK (status IN ('ACTIVE', 'REVOKED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_portal_customer_push_user_status
    ON portal_customer_push_subscriptions(user_id, status, last_seen_at DESC)
    WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_portal_customer_push_profile_status
    ON portal_customer_push_subscriptions(profile_id, status, last_seen_at DESC)
    WHERE profile_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_portal_customer_push_session_status
    ON portal_customer_push_subscriptions(portal_session_id, status, last_seen_at DESC)
    WHERE portal_session_id IS NOT NULL;
