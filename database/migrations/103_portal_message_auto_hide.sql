ALTER TABLE captive_portal_settings
ADD COLUMN IF NOT EXISTS portal_message_auto_hide_seconds INTEGER NOT NULL DEFAULT 6;

UPDATE captive_portal_settings
SET portal_message_auto_hide_seconds = 6
WHERE portal_message_auto_hide_seconds IS NULL;
