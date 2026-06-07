ALTER TABLE captive_portal_settings
    DROP COLUMN IF EXISTS store_owner_purchase_request_sms_enabled,
    DROP COLUMN IF EXISTS store_owner_purchase_request_sms_message;

CREATE TABLE IF NOT EXISTS store_owner_push_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES physical_store_owners(id) ON DELETE CASCADE,
    store_id UUID REFERENCES physical_stores(id) ON DELETE CASCADE,
    endpoint_hash TEXT NOT NULL,
    subscription_json JSONB NOT NULL,
    device_token_hash TEXT,
    user_agent TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_sent_at TIMESTAMPTZ,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, endpoint_hash)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_owner_push_subscriptions_status_check'
    ) THEN
        ALTER TABLE store_owner_push_subscriptions
            ADD CONSTRAINT store_owner_push_subscriptions_status_check
            CHECK (status IN ('ACTIVE', 'REVOKED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_store_owner_push_owner_status
    ON store_owner_push_subscriptions(owner_id, status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_store_owner_push_store_status
    ON store_owner_push_subscriptions(store_id, status, last_seen_at DESC)
    WHERE store_id IS NOT NULL;

