ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS avatar_notes_json JSONB NOT NULL DEFAULT '{}'::jsonb;
