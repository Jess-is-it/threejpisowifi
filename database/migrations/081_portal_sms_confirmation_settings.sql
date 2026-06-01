ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS portal_sms_sender_id TEXT,
    ADD COLUMN IF NOT EXISTS portal_sms_monthly_credit_limit INTEGER,
    ADD COLUMN IF NOT EXISTS portal_sms_monthly_reset_day INTEGER NOT NULL DEFAULT 1;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'captive_portal_sms_monthly_credit_limit_nonnegative'
    ) THEN
        ALTER TABLE captive_portal_settings
            ADD CONSTRAINT captive_portal_sms_monthly_credit_limit_nonnegative
            CHECK (portal_sms_monthly_credit_limit IS NULL OR portal_sms_monthly_credit_limit >= 0) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'captive_portal_sms_monthly_reset_day_range'
    ) THEN
        ALTER TABLE captive_portal_settings
            ADD CONSTRAINT captive_portal_sms_monthly_reset_day_range
            CHECK (portal_sms_monthly_reset_day BETWEEN 1 AND 31) NOT VALID;
    END IF;
END $$;

ALTER TABLE captive_portal_settings
    VALIDATE CONSTRAINT captive_portal_sms_monthly_credit_limit_nonnegative;

ALTER TABLE captive_portal_settings
    VALIDATE CONSTRAINT captive_portal_sms_monthly_reset_day_range;
