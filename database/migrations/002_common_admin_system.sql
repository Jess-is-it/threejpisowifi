ALTER TABLE admins ADD COLUMN IF NOT EXISTS full_name TEXT;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS email TEXT;

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO app_settings(key, value)
VALUES (
    'system',
    '{
      "branding": {
        "display_name": "3JCentralPisowifi",
        "portal_subtitle": "Source of Truth + Manual RADIUS Test MVP",
        "accent_color": "#206bc4"
      },
      "access": {
        "allow_admin_creation": true,
        "session_minutes": 720
      },
      "backup": {
        "retention_days": 14
      }
    }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
