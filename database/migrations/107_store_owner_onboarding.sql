DO $$
BEGIN
    ALTER TABLE physical_stores DROP CONSTRAINT IF EXISTS physical_stores_status_check;
    ALTER TABLE physical_stores
        ADD CONSTRAINT physical_stores_status_check CHECK (status IN ('SETUP', 'ACTIVE', 'DISABLED'));
END $$;

ALTER TABLE physical_stores
    ALTER COLUMN status SET DEFAULT 'SETUP';

UPDATE physical_stores
SET status = 'SETUP'
WHERE status IS NULL;

ALTER TABLE physical_store_owners
    ADD COLUMN IF NOT EXISTS owner_notes TEXT,
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS activation_sms_sent_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS activation_sms_status_json JSONB NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
    ALTER TABLE physical_store_owners DROP CONSTRAINT IF EXISTS physical_store_owners_status_check;
    ALTER TABLE physical_store_owners
        ADD CONSTRAINT physical_store_owners_status_check CHECK (status IN ('SETUP', 'ACTIVE', 'DISABLED'));
END $$;

ALTER TABLE physical_store_owners
    ALTER COLUMN status SET DEFAULT 'SETUP';

ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS store_owner_activation_sms_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS store_owner_activation_sms_message TEXT NOT NULL DEFAULT 'Welcome to 3J Hotspot, <OWNER>! Your store <STORE> is now active. Store portal: <STORE_PORTAL_URL> Username: <USERNAME> Temporary password: <TEMP_PASSWORD>. Please change your password after login.';
