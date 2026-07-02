CREATE TABLE IF NOT EXISTS store_remittances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_id TEXT UNIQUE NOT NULL,
    store_id UUID NOT NULL REFERENCES physical_stores(id) ON DELETE CASCADE,
    owner_id UUID REFERENCES physical_store_owners(id) ON DELETE SET NULL,
    provider TEXT NOT NULL DEFAULT 'PAYMONGO',
    provider_mode TEXT,
    method TEXT NOT NULL DEFAULT 'CASH_PICKUP',
    status TEXT NOT NULL DEFAULT 'REQUESTED',
    gross_sales_centavos BIGINT NOT NULL DEFAULT 0,
    amount_centavos BIGINT NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'PHP',
    sales_period_start DATE NOT NULL DEFAULT date_trunc('month', now())::date,
    sales_period_end DATE NOT NULL DEFAULT now()::date,
    checkout_session_id TEXT,
    checkout_url TEXT,
    provider_payment_id TEXT,
    provider_event_id TEXT,
    provider_response_json JSONB,
    provider_webhook_json JSONB,
    pickup_requested_at TIMESTAMPTZ,
    pickup_scheduled_at TIMESTAMPTZ,
    pickup_completed_at TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    requested_by_owner_id UUID REFERENCES physical_store_owners(id) ON DELETE SET NULL,
    scheduled_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    completed_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    last_error TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_remittances_method_check'
    ) THEN
        ALTER TABLE store_remittances
            ADD CONSTRAINT store_remittances_method_check
            CHECK (method IN ('ONLINE', 'CASH_PICKUP', 'MANUAL_CASH_PICKUP'));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_remittances_status_check'
    ) THEN
        ALTER TABLE store_remittances
            ADD CONSTRAINT store_remittances_status_check
            CHECK (status IN ('REQUESTED', 'CHECKOUT_CREATED', 'PAID', 'CASH_PICKUP_REQUESTED', 'CASH_PICKUP_SCHEDULED', 'COLLECTED', 'FAILED', 'CANCELLED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_store_remittances_store_status
    ON store_remittances(store_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_store_remittances_checkout_session
    ON store_remittances(checkout_session_id)
    WHERE checkout_session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_store_remittances_period
    ON store_remittances(store_id, sales_period_start, sales_period_end);

ALTER TABLE store_purchase_requests
    ADD COLUMN IF NOT EXISTS remittance_id UUID REFERENCES store_remittances(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_store_purchase_requests_remittance
    ON store_purchase_requests(remittance_id)
    WHERE remittance_id IS NOT NULL;
