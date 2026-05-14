CREATE TABLE IF NOT EXISTS mikrotik_pilot_selection (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE CASCADE,
    selected_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    reason TEXT,
    physical_recovery_confidence TEXT CHECK (
        physical_recovery_confidence IS NULL OR physical_recovery_confidence IN (
            'EASY_TO_RECOVER',
            'MODERATE',
            'HARD_REMOTE_SITE'
        )
    ),
    operator_note TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'CLEARED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mikrotik_pilot_selection_one_active
    ON mikrotik_pilot_selection(status)
    WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_mikrotik_pilot_selection_router
    ON mikrotik_pilot_selection(router_id, created_at DESC);

CREATE TABLE IF NOT EXISTS mikrotik_ai_smoke_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'FAILED', 'DISABLED')),
    prompt_summary TEXT,
    response_summary TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_ai_smoke_tests_created
    ON mikrotik_ai_smoke_tests(created_at DESC);
