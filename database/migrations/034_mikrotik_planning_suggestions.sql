ALTER TABLE mikrotik_deployment_questions
    ADD COLUMN IF NOT EXISTS suggested_value TEXT,
    ADD COLUMN IF NOT EXISTS approved_value TEXT,
    ADD COLUMN IF NOT EXISTS answer_status TEXT NOT NULL DEFAULT 'EMPTY',
    ADD COLUMN IF NOT EXISTS suggestion_reason TEXT,
    ADD COLUMN IF NOT EXISTS suggestion_confidence TEXT,
    ADD COLUMN IF NOT EXISTS suggestion_requires_review BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS derived_from TEXT,
    ADD COLUMN IF NOT EXISTS is_derived BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS validation_status TEXT,
    ADD COLUMN IF NOT EXISTS validation_errors_json JSONB,
    ADD COLUMN IF NOT EXISTS updated_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'mikrotik_deployment_questions_answer_status_check'
    ) THEN
        ALTER TABLE mikrotik_deployment_questions
            ADD CONSTRAINT mikrotik_deployment_questions_answer_status_check
            CHECK (answer_status IN ('EMPTY', 'AI_SUGGESTED', 'USER_EDITED', 'APPROVED', 'LOCKED', 'REJECTED'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS mikrotik_planning_derivations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE CASCADE,
    source_question_key TEXT NOT NULL,
    target_question_key TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    reason TEXT,
    applied BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_planning_derivations_router
    ON mikrotik_planning_derivations(router_id, created_at DESC);

CREATE TABLE IF NOT EXISTS mikrotik_ai_planning_suggestions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE CASCADE,
    admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    prompt_summary TEXT,
    suggestions_json JSONB,
    warnings_json JSONB,
    status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'FAILED')),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_ai_planning_suggestions_router
    ON mikrotik_ai_planning_suggestions(router_id, created_at DESC);
