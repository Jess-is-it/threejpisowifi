UPDATE product_items
SET category_id = NULL,
    updated_at = now()
WHERE category_id IS NOT NULL;
