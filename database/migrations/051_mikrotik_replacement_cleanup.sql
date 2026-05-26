ALTER TABLE mikrotik_ap_management_configs
    ADD COLUMN IF NOT EXISTS pending_cleanup_plan_json JSONB,
    ADD COLUMN IF NOT EXISTS pending_cleanup_reason TEXT,
    ADD COLUMN IF NOT EXISTS pending_cleanup_created_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pending_cleanup_resolved_at TIMESTAMPTZ;

ALTER TABLE mikrotik_stations
    ADD COLUMN IF NOT EXISTS pending_cleanup_plan_json JSONB,
    ADD COLUMN IF NOT EXISTS pending_cleanup_reason TEXT,
    ADD COLUMN IF NOT EXISTS pending_cleanup_created_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pending_cleanup_resolved_at TIMESTAMPTZ;
