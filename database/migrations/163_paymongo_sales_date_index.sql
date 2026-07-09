CREATE INDEX IF NOT EXISTS idx_payment_orders_paymongo_online_paid_sale_at
  ON payment_orders ((COALESCE(paid_at, updated_at, created_at)) DESC)
  WHERE provider = 'PAYMONGO'
    AND physical_store_id IS NULL
    AND status = 'PAID';
