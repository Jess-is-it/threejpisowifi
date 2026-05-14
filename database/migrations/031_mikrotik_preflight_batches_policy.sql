CREATE TABLE IF NOT EXISTS mikrotik_preflight_scan_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'SUCCESS', 'PARTIAL_SUCCESS', 'FAILED')),
    started_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    total_routers INTEGER NOT NULL DEFAULT 0,
    scanned_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    max_concurrency INTEGER NOT NULL DEFAULT 3,
    summary_json JSONB,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mikrotik_preflight_scan_batch_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES mikrotik_preflight_scan_batches(id) ON DELETE CASCADE,
    router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES mikrotik_preflight_scans(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'SUCCESS', 'FAILED', 'SKIPPED')),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE mikrotik_preflight_scans
    ADD COLUMN IF NOT EXISTS batch_id UUID REFERENCES mikrotik_preflight_scan_batches(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS policy_result_json JSONB,
    ADD COLUMN IF NOT EXISTS confirmed_deployment_mode TEXT CHECK (
        confirmed_deployment_mode IS NULL OR confirmed_deployment_mode IN (
            'HOTSPOT_GATEWAY',
            'VLAN_TRUNK_HELPER',
            'READ_ONLY_CORE',
            'ISP_BACKUP_TRANSPORT',
            'UNKNOWN_NEEDS_REVIEW'
        )
    ),
    ADD COLUMN IF NOT EXISTS deployment_mode_confirmed_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS deployment_mode_confirmed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS confirmed_router_role TEXT,
    ADD COLUMN IF NOT EXISTS setup_blocked BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS setup_block_reason TEXT;

CREATE TABLE IF NOT EXISTS mikrotik_deployment_policy_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES mikrotik_preflight_scans(id) ON DELETE CASCADE,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'BLOCKED')),
    role_guess TEXT,
    recommended_deployment_mode TEXT NOT NULL CHECK (
        recommended_deployment_mode IN (
            'HOTSPOT_GATEWAY',
            'VLAN_TRUNK_HELPER',
            'READ_ONLY_CORE',
            'ISP_BACKUP_TRANSPORT',
            'UNKNOWN_NEEDS_REVIEW'
        )
    ),
    confirmed_router_role TEXT,
    confirmed_deployment_mode TEXT CHECK (
        confirmed_deployment_mode IS NULL OR confirmed_deployment_mode IN (
            'HOTSPOT_GATEWAY',
            'VLAN_TRUNK_HELPER',
            'READ_ONLY_CORE',
            'ISP_BACKUP_TRANSPORT',
            'UNKNOWN_NEEDS_REVIEW'
        )
    ),
    setup_allowed BOOLEAN NOT NULL DEFAULT false,
    requires_expert_override BOOLEAN NOT NULL DEFAULT false,
    expert_override_enabled BOOLEAN NOT NULL DEFAULT false,
    expert_override_reason TEXT,
    expert_override_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    expert_override_at TIMESTAMPTZ,
    blocking_reasons_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    warnings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    next_questions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_scan_batches_created
    ON mikrotik_preflight_scan_batches(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_scan_batch_items_batch
    ON mikrotik_preflight_scan_batch_items(batch_id);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_scan_batch_items_router
    ON mikrotik_preflight_scan_batch_items(router_id);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_scans_batch
    ON mikrotik_preflight_scans(batch_id);

CREATE INDEX IF NOT EXISTS idx_mikrotik_deployment_policy_results_router_created
    ON mikrotik_deployment_policy_results(router_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_deployment_policy_results_scan
    ON mikrotik_deployment_policy_results(scan_id);
