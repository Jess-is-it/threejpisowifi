ALTER TABLE customer_bag_items
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS admin_created_by UUID,
  ADD COLUMN IF NOT EXISTS admin_updated_by UUID;

CREATE INDEX IF NOT EXISTS idx_customer_bag_items_expires_at
  ON customer_bag_items(expires_at)
  WHERE expires_at IS NOT NULL;
