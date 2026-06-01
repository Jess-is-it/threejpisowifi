ALTER TABLE product_items
    ADD COLUMN IF NOT EXISTS enabled_category_discount_ids JSONB;
