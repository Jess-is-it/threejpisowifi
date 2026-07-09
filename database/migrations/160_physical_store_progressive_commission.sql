ALTER TABLE physical_stores
    ADD COLUMN IF NOT EXISTS commission_tiers_json JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE physical_stores
SET commission_tiers_json = '[
  {"threshold_centavos": 100000, "rate_percent": 10},
  {"threshold_centavos": 200000, "rate_percent": 12},
  {"threshold_centavos": 300000, "rate_percent": 15},
  {"threshold_centavos": 500000, "rate_percent": 18},
  {"threshold_centavos": 1000000, "rate_percent": 22}
]'::jsonb
WHERE commission_type = 'PROGRESSIVE_PERCENT'
  AND (commission_tiers_json IS NULL OR jsonb_array_length(commission_tiers_json) = 0);

DO $$
BEGIN
    ALTER TABLE physical_stores DROP CONSTRAINT IF EXISTS physical_stores_commission_type_check;
    ALTER TABLE physical_stores
        ADD CONSTRAINT physical_stores_commission_type_check
        CHECK (commission_type IN ('PERCENT_OF_SALES', 'FIXED_MONTHLY', 'PROGRESSIVE_PERCENT'));

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
