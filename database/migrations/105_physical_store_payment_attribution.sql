ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS physical_store_id UUID REFERENCES physical_stores(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS physical_store_item_id UUID REFERENCES physical_store_items(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_payment_orders_physical_store_id
    ON payment_orders(physical_store_id)
    WHERE physical_store_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_payment_orders_physical_store_item_id
    ON payment_orders(physical_store_item_id)
    WHERE physical_store_item_id IS NOT NULL;
