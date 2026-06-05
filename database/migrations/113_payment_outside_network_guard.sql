ALTER TABLE payment_orders
  ADD COLUMN IF NOT EXISTS outside_network_purchase BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_payment_orders_outside_network_purchase
  ON payment_orders(outside_network_purchase, status, fulfillment_status);
