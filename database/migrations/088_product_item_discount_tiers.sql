ALTER TABLE product_items
    ADD COLUMN IF NOT EXISTS discount_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS discount_min_quantity INTEGER,
    ADD COLUMN IF NOT EXISTS discount_type TEXT,
    ADD COLUMN IF NOT EXISTS discount_value NUMERIC(12,2) NOT NULL DEFAULT 0;

UPDATE product_items
SET discount_enabled = FALSE
WHERE discount_enabled IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'product_items_discount_type_check'
    ) THEN
        ALTER TABLE product_items
            ADD CONSTRAINT product_items_discount_type_check
            CHECK (discount_type IS NULL OR discount_type IN ('PERCENT', 'FIXED'));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'product_items_discount_min_quantity_check'
    ) THEN
        ALTER TABLE product_items
            ADD CONSTRAINT product_items_discount_min_quantity_check
            CHECK (discount_min_quantity IS NULL OR discount_min_quantity BETWEEN 2 AND 365);
    END IF;
END $$;

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS purchase_quantity INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS base_amount_centavos INTEGER,
    ADD COLUMN IF NOT EXISTS discount_type TEXT,
    ADD COLUMN IF NOT EXISTS discount_value NUMERIC(12,2),
    ADD COLUMN IF NOT EXISTS discount_amount_centavos INTEGER NOT NULL DEFAULT 0;

UPDATE payment_orders
SET purchase_quantity = 1
WHERE purchase_quantity IS NULL OR purchase_quantity < 1;

UPDATE payment_orders
SET base_amount_centavos = amount_centavos
WHERE base_amount_centavos IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'payment_orders_purchase_quantity_check'
    ) THEN
        ALTER TABLE payment_orders
            ADD CONSTRAINT payment_orders_purchase_quantity_check
            CHECK (purchase_quantity BETWEEN 1 AND 365);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'payment_orders_discount_type_check'
    ) THEN
        ALTER TABLE payment_orders
            ADD CONSTRAINT payment_orders_discount_type_check
            CHECK (discount_type IS NULL OR discount_type IN ('PERCENT', 'FIXED'));
    END IF;
END $$;
