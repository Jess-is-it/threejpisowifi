ALTER TABLE product_items
    ADD COLUMN IF NOT EXISTS product_kind TEXT NOT NULL DEFAULT 'WIFI',
    ADD COLUMN IF NOT EXISTS iptv_package_label TEXT,
    ADD COLUMN IF NOT EXISTS iptv_xui_package_id TEXT,
    ADD COLUMN IF NOT EXISTS iptv_auto_provision BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS iptv_notes TEXT;

UPDATE product_items
SET product_kind = 'WIFI'
WHERE product_kind IS NULL OR product_kind NOT IN ('WIFI', 'IPTV', 'WIFI_IPTV');

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'product_items_product_kind_check'
    ) THEN
        ALTER TABLE product_items
            ADD CONSTRAINT product_items_product_kind_check
            CHECK (product_kind IN ('WIFI', 'IPTV', 'WIFI_IPTV'));
    END IF;
END $$;

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS product_kind TEXT NOT NULL DEFAULT 'WIFI',
    ADD COLUMN IF NOT EXISTS iptv_package_label TEXT,
    ADD COLUMN IF NOT EXISTS iptv_xui_package_id TEXT;

UPDATE payment_orders
SET product_kind = 'WIFI'
WHERE product_kind IS NULL OR product_kind NOT IN ('WIFI', 'IPTV', 'WIFI_IPTV');

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'payment_orders_product_kind_check'
    ) THEN
        ALTER TABLE payment_orders
            ADD CONSTRAINT payment_orders_product_kind_check
            CHECK (product_kind IN ('WIFI', 'IPTV', 'WIFI_IPTV'));
    END IF;
END $$;

ALTER TABLE customer_bag_items
    ADD COLUMN IF NOT EXISTS product_kind TEXT NOT NULL DEFAULT 'WIFI',
    ADD COLUMN IF NOT EXISTS iptv_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
    ADD COLUMN IF NOT EXISTS iptv_package_label TEXT,
    ADD COLUMN IF NOT EXISTS iptv_xui_package_id TEXT,
    ADD COLUMN IF NOT EXISTS iptv_account_username TEXT,
    ADD COLUMN IF NOT EXISTS iptv_account_expires_at TIMESTAMPTZ;

UPDATE customer_bag_items
SET product_kind = 'WIFI'
WHERE product_kind IS NULL OR product_kind NOT IN ('WIFI', 'IPTV', 'WIFI_IPTV');

UPDATE customer_bag_items
SET iptv_status = 'NOT_REQUIRED'
WHERE iptv_status IS NULL OR iptv_status NOT IN ('NOT_REQUIRED', 'PENDING', 'MANUAL_REVIEW', 'PROVISIONED', 'FAILED');

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'customer_bag_items_product_kind_check'
    ) THEN
        ALTER TABLE customer_bag_items
            ADD CONSTRAINT customer_bag_items_product_kind_check
            CHECK (product_kind IN ('WIFI', 'IPTV', 'WIFI_IPTV'));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'customer_bag_items_iptv_status_check'
    ) THEN
        ALTER TABLE customer_bag_items
            ADD CONSTRAINT customer_bag_items_iptv_status_check
            CHECK (iptv_status IN ('NOT_REQUIRED', 'PENDING', 'MANUAL_REVIEW', 'PROVISIONED', 'FAILED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_product_items_product_kind
    ON product_items(product_kind, status);

CREATE INDEX IF NOT EXISTS idx_customer_bag_items_iptv_status
    ON customer_bag_items(iptv_status, product_kind);
