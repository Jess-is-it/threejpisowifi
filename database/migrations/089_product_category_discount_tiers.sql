ALTER TABLE product_items
    ADD COLUMN IF NOT EXISTS use_category_discounts BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS product_category_discounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id UUID NOT NULL REFERENCES product_categories(id) ON DELETE CASCADE,
    label TEXT,
    threshold_value INTEGER NOT NULL CHECK (threshold_value > 0),
    threshold_unit TEXT NOT NULL DEFAULT 'days' CHECK (threshold_unit IN ('minutes', 'hours', 'days')),
    discount_type TEXT NOT NULL CHECK (discount_type IN ('PERCENT', 'FIXED')),
    discount_value NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (discount_value >= 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_product_category_discounts_category
    ON product_category_discounts(category_id, enabled, sort_order, threshold_unit, threshold_value);
