CREATE TABLE IF NOT EXISTS store_owner_suki_customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_id UUID NOT NULL REFERENCES physical_stores(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES physical_store_owners(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(store_id, user_id)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_owner_suki_customers_status_check'
    ) THEN
        ALTER TABLE store_owner_suki_customers
            ADD CONSTRAINT store_owner_suki_customers_status_check
            CHECK (status IN ('ACTIVE', 'REMOVED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_store_owner_suki_customers_owner_status
    ON store_owner_suki_customers(owner_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_store_owner_suki_customers_store_user
    ON store_owner_suki_customers(store_id, user_id);
