ALTER TABLE portal_customer_profiles
    ADD COLUMN IF NOT EXISTS portal_notifications_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS portal_notification_interval_seconds INTEGER NOT NULL DEFAULT 10,
    ADD COLUMN IF NOT EXISTS portal_notification_sent_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS portal_notification_last_sent_at TIMESTAMPTZ;

ALTER TABLE portal_customer_profiles
    DROP CONSTRAINT IF EXISTS portal_customer_profiles_notification_interval_positive;

ALTER TABLE portal_customer_profiles
    ADD CONSTRAINT portal_customer_profiles_notification_interval_positive
    CHECK (portal_notification_interval_seconds >= 1) NOT VALID;

ALTER TABLE portal_customer_profiles
    VALIDATE CONSTRAINT portal_customer_profiles_notification_interval_positive;
