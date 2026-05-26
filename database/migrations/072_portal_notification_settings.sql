ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS portal_notifications_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS portal_success_notification_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS portal_success_notification_message TEXT NOT NULL DEFAULT 'Voucher accepted. Remaining time: <TIME>.',
    ADD COLUMN IF NOT EXISTS portal_remaining_notification_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS portal_remaining_notification_trigger_seconds INTEGER NOT NULL DEFAULT 300,
    ADD COLUMN IF NOT EXISTS portal_remaining_notification_message TEXT NOT NULL DEFAULT 'Reminder: only <TIME> remaining on your WiFi voucher.',
    ADD COLUMN IF NOT EXISTS portal_expired_notification_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS portal_expired_notification_message TEXT NOT NULL DEFAULT 'Your WiFi voucher time is fully consumed. Enter a new voucher to continue.',
    ADD COLUMN IF NOT EXISTS portal_reconnect_notification_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS portal_reconnect_notification_message TEXT NOT NULL DEFAULT 'Your WiFi session was restored. Remaining time: <TIME>.';

ALTER TABLE captive_portal_settings
    ADD CONSTRAINT captive_portal_remaining_notification_trigger_nonnegative
    CHECK (portal_remaining_notification_trigger_seconds >= 0) NOT VALID;

ALTER TABLE captive_portal_settings
    VALIDATE CONSTRAINT captive_portal_remaining_notification_trigger_nonnegative;
