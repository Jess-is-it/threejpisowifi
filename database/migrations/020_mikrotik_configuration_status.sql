ALTER TABLE mikrotik_routers
    ADD COLUMN IF NOT EXISTS configuration_status TEXT NOT NULL DEFAULT 'NOT_REVIEWED'
        CHECK (configuration_status IN ('NOT_REVIEWED', 'REVIEWED', 'APPLIED', 'FAILED')),
    ADD COLUMN IF NOT EXISTS last_configuration_review_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_configuration_apply_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_configuration_error TEXT;

CREATE INDEX IF NOT EXISTS idx_mikrotik_routers_configuration_status
    ON mikrotik_routers(configuration_status);
