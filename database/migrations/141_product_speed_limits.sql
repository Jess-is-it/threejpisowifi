ALTER TABLE product_items
    ADD COLUMN IF NOT EXISTS speed_limit_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS speed_download_mbps NUMERIC(10,2),
    ADD COLUMN IF NOT EXISTS speed_upload_mbps NUMERIC(10,2);

ALTER TABLE physical_store_items
    ADD COLUMN IF NOT EXISTS speed_limit_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS speed_download_mbps NUMERIC(10,2),
    ADD COLUMN IF NOT EXISTS speed_upload_mbps NUMERIC(10,2);

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS speed_limit_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS speed_download_mbps NUMERIC(10,2),
    ADD COLUMN IF NOT EXISTS speed_upload_mbps NUMERIC(10,2);

ALTER TABLE store_purchase_request_items
    ADD COLUMN IF NOT EXISTS speed_limit_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS speed_download_mbps NUMERIC(10,2),
    ADD COLUMN IF NOT EXISTS speed_upload_mbps NUMERIC(10,2);

ALTER TABLE customer_bag_items
    ADD COLUMN IF NOT EXISTS speed_limit_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS speed_download_mbps NUMERIC(10,2),
    ADD COLUMN IF NOT EXISTS speed_upload_mbps NUMERIC(10,2),
    ADD COLUMN IF NOT EXISTS speed_limit_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
    ADD COLUMN IF NOT EXISTS speed_limit_router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS speed_limit_queue_name TEXT,
    ADD COLUMN IF NOT EXISTS speed_limit_target_ip INET,
    ADD COLUMN IF NOT EXISTS speed_limit_applied_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS speed_limit_last_error TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'product_items_speed_download_check'
    ) THEN
        ALTER TABLE product_items
            ADD CONSTRAINT product_items_speed_download_check CHECK (speed_download_mbps IS NULL OR speed_download_mbps >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'product_items_speed_upload_check'
    ) THEN
        ALTER TABLE product_items
            ADD CONSTRAINT product_items_speed_upload_check CHECK (speed_upload_mbps IS NULL OR speed_upload_mbps >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_items_speed_download_check'
    ) THEN
        ALTER TABLE physical_store_items
            ADD CONSTRAINT physical_store_items_speed_download_check CHECK (speed_download_mbps IS NULL OR speed_download_mbps >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_items_speed_upload_check'
    ) THEN
        ALTER TABLE physical_store_items
            ADD CONSTRAINT physical_store_items_speed_upload_check CHECK (speed_upload_mbps IS NULL OR speed_upload_mbps >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'customer_bag_items_speed_limit_status_check'
    ) THEN
        ALTER TABLE customer_bag_items
            ADD CONSTRAINT customer_bag_items_speed_limit_status_check
            CHECK (speed_limit_status IN ('NOT_REQUIRED', 'PENDING', 'APPLIED', 'FAILED', 'REMOVED', 'SUPERSEDED'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS portal_speed_limit_queues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portal_session_id UUID NOT NULL UNIQUE REFERENCES portal_sessions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    station_id UUID REFERENCES mikrotik_stations(id) ON DELETE SET NULL,
    router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    selected_bag_item_id UUID REFERENCES customer_bag_items(id) ON DELETE SET NULL,
    queue_name TEXT NOT NULL,
    target_ip INET,
    upload_mbps NUMERIC(10,2),
    download_mbps NUMERIC(10,2),
    status TEXT NOT NULL DEFAULT 'PENDING',
    last_error TEXT,
    applied_at TIMESTAMPTZ,
    removed_at TIMESTAMPTZ,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'portal_speed_limit_queues_status_check'
    ) THEN
        ALTER TABLE portal_speed_limit_queues
            ADD CONSTRAINT portal_speed_limit_queues_status_check
            CHECK (status IN ('PENDING', 'APPLIED', 'FAILED', 'REMOVED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_portal_speed_limit_queues_status
    ON portal_speed_limit_queues(status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_portal_speed_limit_queues_router
    ON portal_speed_limit_queues(router_id, status)
    WHERE router_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_customer_bag_items_speed_limit
    ON customer_bag_items(speed_limit_enabled, speed_limit_status, portal_session_id)
    WHERE speed_limit_enabled = true;
