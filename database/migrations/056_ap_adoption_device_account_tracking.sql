ALTER TABLE ap_deployments
    ADD COLUMN IF NOT EXISTS adoption_device_account_username TEXT,
    ADD COLUMN IF NOT EXISTS adoption_device_account_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS adoption_device_account_applied BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS adoption_device_account_applied_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_ap_deployments_adoption_device_account
    ON ap_deployments(adoption_device_account_applied, adoption_device_account_username);
