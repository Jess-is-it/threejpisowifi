DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_remittances_status_check'
    ) THEN
        ALTER TABLE store_remittances DROP CONSTRAINT store_remittances_status_check;
    END IF;
    ALTER TABLE store_remittances
        ADD CONSTRAINT store_remittances_status_check
        CHECK (status IN ('REQUESTED', 'CHECKOUT_CREATED', 'PAID', 'CASH_PICKUP_REQUESTED', 'CASH_PICKUP_SCHEDULED', 'COLLECTED', 'FAILED', 'CANCELLED', 'EXPIRED'));
END $$;

UPDATE store_remittances
SET status = 'EXPIRED',
    last_error = COALESCE(NULLIF(last_error, ''), 'Online checkout expired before payment was completed.'),
    updated_at = now()
WHERE method = 'ONLINE'
  AND status = 'CHECKOUT_CREATED'
  AND created_at <= now() - interval '30 minutes';

UPDATE store_purchase_requests spr
SET remittance_id = NULL,
    updated_at = now()
FROM store_remittances sr
WHERE spr.remittance_id = sr.id
  AND sr.status IN ('CANCELLED', 'FAILED', 'EXPIRED');
