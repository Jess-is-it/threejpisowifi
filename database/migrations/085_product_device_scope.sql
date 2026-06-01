ALTER TABLE product_items
    ADD COLUMN IF NOT EXISTS device_scope TEXT NOT NULL DEFAULT 'SINGLE_DEVICE';

UPDATE product_items
SET device_scope = CASE WHEN COALESCE(allowed_devices, 1) > 1 THEN 'MULTI_DEVICE' ELSE 'SINGLE_DEVICE' END;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'product_items_device_scope_check'
    ) THEN
        ALTER TABLE product_items
            ADD CONSTRAINT product_items_device_scope_check CHECK (device_scope IN ('SINGLE_DEVICE', 'MULTI_DEVICE'));
    END IF;
END $$;

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS device_scope TEXT NOT NULL DEFAULT 'SINGLE_DEVICE';

UPDATE payment_orders
SET device_scope = CASE WHEN COALESCE(allowed_devices, 1) > 1 THEN 'MULTI_DEVICE' ELSE 'SINGLE_DEVICE' END;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'payment_orders_device_scope_check'
    ) THEN
        ALTER TABLE payment_orders
            ADD CONSTRAINT payment_orders_device_scope_check CHECK (device_scope IN ('SINGLE_DEVICE', 'MULTI_DEVICE'));
    END IF;
END $$;
