ALTER TABLE iptv_accounts
    ADD COLUMN IF NOT EXISTS bag_item_id UUID REFERENCES customer_bag_items(id) ON DELETE SET NULL;

ALTER TABLE iptv_accounts
    DROP CONSTRAINT IF EXISTS iptv_accounts_user_id_key;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'iptv_accounts_status_check'
    ) THEN
        ALTER TABLE iptv_accounts DROP CONSTRAINT iptv_accounts_status_check;
    END IF;

    ALTER TABLE iptv_accounts
        ADD CONSTRAINT iptv_accounts_status_check
        CHECK (status IN ('PENDING', 'PROVISIONED', 'FAILED', 'DISABLED', 'DELETED'));
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'iptv_provisioning_jobs_action_check'
    ) THEN
        ALTER TABLE iptv_provisioning_jobs DROP CONSTRAINT iptv_provisioning_jobs_action_check;
    END IF;

    ALTER TABLE iptv_provisioning_jobs
        ADD CONSTRAINT iptv_provisioning_jobs_action_check
        CHECK (action IN ('CREATE_OR_EXTEND', 'CREATE', 'EXTEND', 'DELETE'));
END $$;

WITH latest_job AS (
    SELECT DISTINCT ON (iptv_account_id)
        iptv_account_id,
        bag_item_id
    FROM iptv_provisioning_jobs
    WHERE iptv_account_id IS NOT NULL
    ORDER BY iptv_account_id, created_at DESC
)
UPDATE iptv_accounts account
SET bag_item_id = latest_job.bag_item_id,
    updated_at = now()
FROM latest_job
WHERE account.id = latest_job.iptv_account_id
  AND account.bag_item_id IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM iptv_accounts other
      WHERE other.bag_item_id = latest_job.bag_item_id
        AND other.id <> account.id
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_iptv_accounts_bag_item_id_unique
    ON iptv_accounts(bag_item_id)
    WHERE bag_item_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_iptv_accounts_user_bag_status
    ON iptv_accounts(user_id, bag_item_id, status);
