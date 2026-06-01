CREATE TABLE IF NOT EXISTS product_categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    access_scope TEXT NOT NULL DEFAULT 'ALL_LOCATIONS',
    allowed_barangay TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'product_categories_access_scope_check'
    ) THEN
        ALTER TABLE product_categories
            ADD CONSTRAINT product_categories_access_scope_check CHECK (access_scope IN ('ALL_LOCATIONS', 'BARANGAY_ONLY'));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'product_categories_status_check'
    ) THEN
        ALTER TABLE product_categories
            ADD CONSTRAINT product_categories_status_check CHECK (status IN ('ACTIVE', 'DISABLED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_product_categories_status_sort
    ON product_categories(status, sort_order, created_at);

CREATE INDEX IF NOT EXISTS idx_product_categories_barangay
    ON product_categories(lower(allowed_barangay));

ALTER TABLE product_items
    ADD COLUMN IF NOT EXISTS category_id UUID REFERENCES product_categories(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_product_items_category_id
    ON product_items(category_id);

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS product_category_id UUID REFERENCES product_categories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS product_category_name TEXT,
    ADD COLUMN IF NOT EXISTS product_category_access_scope TEXT NOT NULL DEFAULT 'ALL_LOCATIONS',
    ADD COLUMN IF NOT EXISTS product_category_barangay TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'payment_orders_product_category_access_scope_check'
    ) THEN
        ALTER TABLE payment_orders
            ADD CONSTRAINT payment_orders_product_category_access_scope_check CHECK (product_category_access_scope IN ('ALL_LOCATIONS', 'BARANGAY_ONLY'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_payment_orders_product_category_id
    ON payment_orders(product_category_id);

ALTER TABLE vouchers
    ADD COLUMN IF NOT EXISTS product_category_id UUID REFERENCES product_categories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS access_scope TEXT NOT NULL DEFAULT 'ALL_LOCATIONS',
    ADD COLUMN IF NOT EXISTS allowed_barangay TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'vouchers_access_scope_check'
    ) THEN
        ALTER TABLE vouchers
            ADD CONSTRAINT vouchers_access_scope_check CHECK (access_scope IN ('ALL_LOCATIONS', 'BARANGAY_ONLY'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_vouchers_product_category_id
    ON vouchers(product_category_id);

CREATE INDEX IF NOT EXISTS idx_vouchers_access_scope_barangay
    ON vouchers(access_scope, lower(allowed_barangay));
