CREATE TABLE IF NOT EXISTS mikrotik_ai_conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    scan_batch_id UUID REFERENCES mikrotik_preflight_scan_batches(id) ON DELETE SET NULL,
    title TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mikrotik_ai_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES mikrotik_ai_conversations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('USER', 'ASSISTANT', 'SYSTEM')),
    message_text TEXT NOT NULL,
    sanitized_context_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mikrotik_deployment_questions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE CASCADE,
    question_key TEXT NOT NULL,
    question_text TEXT NOT NULL,
    answer_value TEXT,
    answered_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    answered_at TIMESTAMPTZ,
    required_for_preview BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(router_id, question_key)
);

CREATE TABLE IF NOT EXISTS mikrotik_draft_deployment_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_id UUID NOT NULL REFERENCES mikrotik_routers(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES mikrotik_preflight_scans(id) ON DELETE SET NULL,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    ai_generated BOOLEAN NOT NULL DEFAULT true,
    plan_json JSONB NOT NULL,
    validation_status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (validation_status IN ('DRAFT', 'PASS', 'WARNING', 'BLOCKED')),
    validation_result_json JSONB,
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'READY_FOR_COMMAND_PREVIEW', 'REJECTED', 'SUPERSEDED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_ai_conversations_admin
    ON mikrotik_ai_conversations(admin_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_ai_conversations_router
    ON mikrotik_ai_conversations(router_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_ai_messages_conversation
    ON mikrotik_ai_messages(conversation_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_deployment_questions_router
    ON mikrotik_deployment_questions(router_id);

CREATE INDEX IF NOT EXISTS idx_mikrotik_draft_plans_router
    ON mikrotik_draft_deployment_plans(router_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_draft_plans_status
    ON mikrotik_draft_deployment_plans(status, validation_status);
