ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS portal_welcome_sms_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS portal_welcome_sms_message TEXT NOT NULL DEFAULT 'Welcome to 3J WiFi, <USER>! For a better experience, open net.3jhotspot.com in Google Chrome when checking your time, buying WiFi, or managing your profile.';

