ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS no_internet_subtitle TEXT NOT NULL DEFAULT 'Connect with a voucher or buy a WiFi package.';
