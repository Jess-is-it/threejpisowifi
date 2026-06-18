ALTER TABLE iptv_accounts
    ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deletion_eligible_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deletion_reason TEXT;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'iptv_accounts_status_check'
    ) THEN
        ALTER TABLE iptv_accounts DROP CONSTRAINT iptv_accounts_status_check;
    END IF;

    ALTER TABLE iptv_accounts
        ADD CONSTRAINT iptv_accounts_status_check
        CHECK (status IN ('PENDING', 'PROVISIONED', 'FAILED', 'DISABLED', 'PENDING_DELETE', 'DELETED'));
END $$;

CREATE INDEX IF NOT EXISTS idx_iptv_accounts_pending_delete
    ON iptv_accounts(status, deletion_eligible_at)
    WHERE status = 'PENDING_DELETE';
