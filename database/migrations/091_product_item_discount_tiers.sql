CREATE TABLE IF NOT EXISTS product_item_discounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_item_id UUID NOT NULL REFERENCES product_items(id) ON DELETE CASCADE,
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

CREATE INDEX IF NOT EXISTS idx_product_item_discounts_item
    ON product_item_discounts(product_item_id, enabled, sort_order, threshold_unit, threshold_value);

INSERT INTO product_item_discounts(
    product_item_id, label, threshold_value, threshold_unit, discount_type,
    discount_value, enabled, sort_order, created_at, updated_at
)
SELECT
    p.id,
    d.label,
    d.threshold_value,
    d.threshold_unit,
    d.discount_type,
    d.discount_value,
    d.enabled,
    d.sort_order,
    now(),
    now()
FROM product_items p
JOIN product_category_discounts d ON d.category_id = p.category_id
WHERE p.use_category_discounts IS DISTINCT FROM FALSE
  AND (
      p.enabled_category_discount_ids IS NULL
      OR EXISTS (
          SELECT 1
          FROM jsonb_array_elements_text(p.enabled_category_discount_ids) selected(id)
          WHERE selected.id = d.id::text
      )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM product_item_discounts existing
      WHERE existing.product_item_id = p.id
        AND COALESCE(existing.label, '') = COALESCE(d.label, '')
        AND existing.threshold_value = d.threshold_value
        AND existing.threshold_unit = d.threshold_unit
        AND existing.discount_type = d.discount_type
        AND existing.discount_value = d.discount_value
  );
