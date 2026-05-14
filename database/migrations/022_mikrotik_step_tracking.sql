ALTER TABLE mikrotik_routers
    ADD COLUMN IF NOT EXISTS configuration_step_status JSONB NOT NULL DEFAULT '{}'::jsonb;

