ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS profile_gift_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS profile_gift_duration_seconds INTEGER NOT NULL DEFAULT 86400,
    ADD COLUMN IF NOT EXISTS profile_gift_title TEXT NOT NULL DEFAULT 'FREE 1Day Welcome Gift',
    ADD COLUMN IF NOT EXISTS profile_gift_available_message TEXT NOT NULL DEFAULT 'Welcome gift waiting',
    ADD COLUMN IF NOT EXISTS profile_gift_description TEXT NOT NULL DEFAULT 'Redeem this once on your verified contact number. It will be hidden after redemption.',
    ADD COLUMN IF NOT EXISTS profile_gift_profile_saved_message TEXT NOT NULL DEFAULT 'Profile saved. You have a FREE 1D welcome gift waiting below your avatar.',
    ADD COLUMN IF NOT EXISTS profile_gift_redeemed_message TEXT NOT NULL DEFAULT 'FREE 1D welcome gift redeemed. You may now use the internet.';

ALTER TABLE captive_portal_settings
    DROP CONSTRAINT IF EXISTS captive_portal_settings_profile_gift_duration_positive;

ALTER TABLE captive_portal_settings
    ADD CONSTRAINT captive_portal_settings_profile_gift_duration_positive
    CHECK (profile_gift_duration_seconds > 0);
