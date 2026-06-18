ALTER TABLE product_items
  ADD COLUMN IF NOT EXISTS item_color_key TEXT,
  ADD COLUMN IF NOT EXISTS item_color_hex TEXT;

ALTER TABLE physical_store_items
  ADD COLUMN IF NOT EXISTS item_color_key TEXT,
  ADD COLUMN IF NOT EXISTS item_color_hex TEXT;

CREATE INDEX IF NOT EXISTS idx_product_items_item_color_key ON product_items(item_color_key);
CREATE INDEX IF NOT EXISTS idx_physical_store_items_item_color_key ON physical_store_items(item_color_key);

WITH palette(ord, color_key, color_hex) AS (
  VALUES
    (1, 'coral', '#fb7185'),
    (2, 'orange', '#f97316'),
    (3, 'amber', '#f59e0b'),
    (4, 'gold', '#eab308'),
    (5, 'lime', '#84cc16'),
    (6, 'emerald', '#10b981'),
    (7, 'mint', '#34d399'),
    (8, 'teal', '#14b8a6'),
    (9, 'aqua', '#06b6d4'),
    (10, 'sky', '#0ea5e9'),
    (11, 'blue', '#3b82f6'),
    (12, 'indigo', '#6366f1'),
    (13, 'violet', '#8b5cf6'),
    (14, 'purple', '#a855f7'),
    (15, 'fuchsia', '#d946ef'),
    (16, 'pink', '#ec4899'),
    (17, 'rose', '#f43f5e'),
    (18, 'red', '#ef4444'),
    (19, 'slate', '#64748b'),
    (20, 'gray', '#6b7280'),
    (21, 'stone', '#78716c'),
    (22, 'pearl', '#f8fafc'),
    (23, 'graphite', '#111827'),
    (24, 'cyan', '#22d3ee')
),
numbered AS (
  SELECT
    id,
    row_number() OVER (ORDER BY sort_order ASC, price ASC, name ASC, created_at ASC) AS rn
  FROM product_items
  WHERE COALESCE(item_color_key, '') = ''
     OR COALESCE(item_color_hex, '') = ''
)
UPDATE product_items item
SET item_color_key = palette.color_key,
    item_color_hex = palette.color_hex,
    updated_at = now()
FROM numbered
JOIN palette ON palette.ord = ((numbered.rn - 1) % 24) + 1
WHERE item.id = numbered.id;

WITH palette(ord, color_key, color_hex) AS (
  VALUES
    (1, 'coral', '#fb7185'),
    (2, 'orange', '#f97316'),
    (3, 'amber', '#f59e0b'),
    (4, 'gold', '#eab308'),
    (5, 'lime', '#84cc16'),
    (6, 'emerald', '#10b981'),
    (7, 'mint', '#34d399'),
    (8, 'teal', '#14b8a6'),
    (9, 'aqua', '#06b6d4'),
    (10, 'sky', '#0ea5e9'),
    (11, 'blue', '#3b82f6'),
    (12, 'indigo', '#6366f1'),
    (13, 'violet', '#8b5cf6'),
    (14, 'purple', '#a855f7'),
    (15, 'fuchsia', '#d946ef'),
    (16, 'pink', '#ec4899'),
    (17, 'rose', '#f43f5e'),
    (18, 'red', '#ef4444'),
    (19, 'slate', '#64748b'),
    (20, 'gray', '#6b7280'),
    (21, 'stone', '#78716c'),
    (22, 'pearl', '#f8fafc'),
    (23, 'graphite', '#111827'),
    (24, 'cyan', '#22d3ee')
),
numbered AS (
  SELECT
    id,
    row_number() OVER (ORDER BY sort_order ASC, price ASC, name ASC, created_at ASC) AS rn
  FROM physical_store_items
  WHERE COALESCE(item_color_key, '') = ''
     OR COALESCE(item_color_hex, '') = ''
)
UPDATE physical_store_items item
SET item_color_key = palette.color_key,
    item_color_hex = palette.color_hex,
    updated_at = now()
FROM numbered
JOIN palette ON palette.ord = ((numbered.rn - 1) % 24) + 1
WHERE item.id = numbered.id;
