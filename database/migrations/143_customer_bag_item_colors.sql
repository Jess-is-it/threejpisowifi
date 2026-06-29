ALTER TABLE customer_bag_items
  ADD COLUMN IF NOT EXISTS item_color_key TEXT,
  ADD COLUMN IF NOT EXISTS item_color_hex TEXT;

CREATE INDEX IF NOT EXISTS idx_customer_bag_items_item_color_key
  ON customer_bag_items(item_color_key);

UPDATE customer_bag_items bag
SET item_color_key = product.item_color_key,
    item_color_hex = product.item_color_hex,
    updated_at = now()
FROM product_items product
WHERE bag.product_item_id = product.id
  AND (COALESCE(bag.item_color_key, '') = '' OR COALESCE(bag.item_color_hex, '') = '')
  AND COALESCE(product.item_color_key, '') <> ''
  AND COALESCE(product.item_color_hex, '') <> '';

WITH store_color AS (
  SELECT DISTINCT ON (request.fulfilled_bag_item_id)
    request.fulfilled_bag_item_id AS bag_item_id,
    item.item_color_key,
    item.item_color_hex
  FROM store_purchase_requests request
  JOIN store_purchase_request_items request_item ON request_item.request_id = request.id
  JOIN physical_store_items item ON item.id = request_item.store_item_id
  WHERE request.fulfilled_bag_item_id IS NOT NULL
    AND COALESCE(item.item_color_key, '') <> ''
    AND COALESCE(item.item_color_hex, '') <> ''
  ORDER BY request.fulfilled_bag_item_id, request_item.created_at ASC
)
UPDATE customer_bag_items bag
SET item_color_key = store_color.item_color_key,
    item_color_hex = store_color.item_color_hex,
    updated_at = now()
FROM store_color
WHERE bag.id = store_color.bag_item_id
  AND (COALESCE(bag.item_color_key, '') = '' OR COALESCE(bag.item_color_hex, '') = '');
