ALTER TABLE physical_stores
    ADD COLUMN IF NOT EXISTS commission_type TEXT NOT NULL DEFAULT 'PERCENT_OF_SALES',
    ADD COLUMN IF NOT EXISTS commission_value NUMERIC(12, 2) NOT NULL DEFAULT 0;

DO $$
BEGIN
    ALTER TABLE physical_stores DROP CONSTRAINT IF EXISTS physical_stores_commission_type_check;
    ALTER TABLE physical_stores
        ADD CONSTRAINT physical_stores_commission_type_check
        CHECK (commission_type IN ('PERCENT_OF_SALES', 'FIXED_MONTHLY'));

    ALTER TABLE physical_stores DROP CONSTRAINT IF EXISTS physical_stores_commission_value_check;
    ALTER TABLE physical_stores
        ADD CONSTRAINT physical_stores_commission_value_check
        CHECK (
            commission_value >= 0
            AND (
                commission_type <> 'PERCENT_OF_SALES'
                OR commission_value <= 100
            )
        );
END $$;
