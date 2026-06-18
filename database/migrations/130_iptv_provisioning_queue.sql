ALTER TABLE customer_bag_items
    ADD COLUMN IF NOT EXISTS iptv_account_id UUID,
    ADD COLUMN IF NOT EXISTS iptv_watch_url TEXT;

CREATE TABLE IF NOT EXISTS iptv_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    xui_user_id TEXT,
    xui_username TEXT NOT NULL UNIQUE,
    xui_password_encrypted TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    all_bouquets BOOLEAN NOT NULL DEFAULT true,
    max_connections INTEGER NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ,
    last_provisioned_at TIMESTAMPTZ,
    last_error TEXT,
    last_response_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'iptv_accounts_status_check'
    ) THEN
        ALTER TABLE iptv_accounts
            ADD CONSTRAINT iptv_accounts_status_check
            CHECK (status IN ('PENDING', 'PROVISIONED', 'FAILED', 'DISABLED'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS iptv_provisioning_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bag_item_id UUID NOT NULL UNIQUE REFERENCES customer_bag_items(id) ON DELETE CASCADE,
    payment_order_id UUID REFERENCES payment_orders(id) ON DELETE SET NULL,
    iptv_account_id UUID REFERENCES iptv_accounts(id) ON DELETE SET NULL,
    action TEXT NOT NULL DEFAULT 'CREATE_OR_EXTEND',
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    requested_duration_seconds INTEGER NOT NULL DEFAULT 0,
    target_expires_at TIMESTAMPTZ,
    xui_username TEXT,
    last_error TEXT,
    last_request_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_response_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'iptv_provisioning_jobs_status_check'
    ) THEN
        ALTER TABLE iptv_provisioning_jobs
            ADD CONSTRAINT iptv_provisioning_jobs_status_check
            CHECK (status IN ('PENDING', 'RUNNING', 'PROVISIONED', 'FAILED', 'SKIPPED'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'iptv_provisioning_jobs_action_check'
    ) THEN
        ALTER TABLE iptv_provisioning_jobs
            ADD CONSTRAINT iptv_provisioning_jobs_action_check
            CHECK (action IN ('CREATE_OR_EXTEND', 'CREATE', 'EXTEND'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS iptv_login_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bag_item_id UUID REFERENCES customer_bag_items(id) ON DELETE SET NULL,
    iptv_account_id UUID REFERENCES iptv_accounts(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_iptv_accounts_status
    ON iptv_accounts(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_iptv_provisioning_jobs_status
    ON iptv_provisioning_jobs(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_iptv_login_tokens_hash
    ON iptv_login_tokens(token_hash, expires_at);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'customer_bag_items_iptv_account_id_fkey'
    ) THEN
        ALTER TABLE customer_bag_items
            ADD CONSTRAINT customer_bag_items_iptv_account_id_fkey
            FOREIGN KEY (iptv_account_id) REFERENCES iptv_accounts(id) ON DELETE SET NULL;
    END IF;
END $$;
