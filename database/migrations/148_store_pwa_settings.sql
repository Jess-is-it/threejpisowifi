ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS store_pwa_settings_json JSONB NOT NULL DEFAULT '{}'::jsonb;
