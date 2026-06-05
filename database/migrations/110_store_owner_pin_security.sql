ALTER TABLE physical_store_owners
    ADD COLUMN IF NOT EXISTS pin_hash TEXT,
    ADD COLUMN IF NOT EXISTS pin_required_interval_minutes INTEGER NOT NULL DEFAULT 5;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_owners_pin_interval_check'
    ) THEN
        ALTER TABLE physical_store_owners
            ADD CONSTRAINT physical_store_owners_pin_interval_check
            CHECK (pin_required_interval_minutes BETWEEN 1 AND 30);
    END IF;
END $$;

ALTER TABLE store_owner_sessions
    ADD COLUMN IF NOT EXISTS pin_verified_until TIMESTAMPTZ;
