CREATE TABLE IF NOT EXISTS product_category_item_assignments (
    category_id UUID NOT NULL REFERENCES product_categories(id) ON DELETE CASCADE,
    item_id UUID NOT NULL REFERENCES product_items(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (category_id, item_id)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'product_category_item_assignments_status_check'
    ) THEN
        ALTER TABLE product_category_item_assignments
            ADD CONSTRAINT product_category_item_assignments_status_check
            CHECK (status IN ('ACTIVE', 'DISABLED'));
    END IF;
END $$;

INSERT INTO product_category_item_assignments(category_id, item_id, status, sort_order)
SELECT p.category_id, p.id, 'ACTIVE', COALESCE(p.sort_order, 0)
FROM product_items p
WHERE p.category_id IS NOT NULL
ON CONFLICT (category_id, item_id) DO UPDATE
SET status = 'ACTIVE',
    sort_order = EXCLUDED.sort_order,
    updated_at = now();

CREATE INDEX IF NOT EXISTS idx_product_category_item_assignments_category
    ON product_category_item_assignments(category_id, status, sort_order);

CREATE INDEX IF NOT EXISTS idx_product_category_item_assignments_item
    ON product_category_item_assignments(item_id, status);
