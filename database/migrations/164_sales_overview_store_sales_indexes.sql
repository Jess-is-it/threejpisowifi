CREATE INDEX IF NOT EXISTS idx_store_purchase_requests_approved_at
  ON store_purchase_requests(approved_at DESC)
  WHERE status = 'APPROVED';

CREATE INDEX IF NOT EXISTS idx_store_purchase_requests_unremitted_lookup
  ON store_purchase_requests(store_id, remittance_id, approved_at DESC)
  WHERE status = 'APPROVED';
