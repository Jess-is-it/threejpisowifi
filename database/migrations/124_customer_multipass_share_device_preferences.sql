ALTER TABLE customer_bag_item_shares
  ADD COLUMN IF NOT EXISTS owner_starred BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE customer_bag_item_shares
  ADD COLUMN IF NOT EXISTS owner_priority INTEGER;

CREATE INDEX IF NOT EXISTS idx_customer_bag_item_shares_owner_starred
  ON customer_bag_item_shares(owner_user_id, owner_starred, owner_priority NULLS LAST, updated_at DESC)
  WHERE shared_user_id IS NOT NULL;
