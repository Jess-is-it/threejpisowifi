ALTER TABLE product_items
    ADD COLUMN IF NOT EXISTS allowed_devices INTEGER NOT NULL DEFAULT 1;

UPDATE product_items
SET allowed_devices = 1
WHERE allowed_devices IS NULL OR allowed_devices < 1;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'product_items_allowed_devices_check'
    ) THEN
        ALTER TABLE product_items
            ADD CONSTRAINT product_items_allowed_devices_check CHECK (allowed_devices >= 1);
    END IF;
END $$;

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS allowed_devices INTEGER NOT NULL DEFAULT 1;

UPDATE payment_orders
SET allowed_devices = 1
WHERE allowed_devices IS NULL OR allowed_devices < 1;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'payment_orders_allowed_devices_check'
    ) THEN
        ALTER TABLE payment_orders
            ADD CONSTRAINT payment_orders_allowed_devices_check CHECK (allowed_devices >= 1);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_payment_orders_paid_at
    ON payment_orders(paid_at DESC);
