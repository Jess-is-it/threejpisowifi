CREATE TABLE IF NOT EXISTS a2p_message_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL DEFAULT 'SMART_MESSAGING_SUITE',
    purpose TEXT,
    destination TEXT,
    destination_masked TEXT,
    source TEXT,
    message_text TEXT,
    message_preview TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED')),
    smart_status TEXT,
    http_status INTEGER,
    message_id TEXT,
    response_summary TEXT,
    error_message TEXT,
    request_context_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_a2p_message_logs_status_created
    ON a2p_message_logs(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_a2p_message_logs_purpose_created
    ON a2p_message_logs(purpose, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_a2p_message_logs_message_id
    ON a2p_message_logs(message_id);

CREATE TABLE IF NOT EXISTS admin_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO'
        CHECK (severity IN ('INFO', 'SUCCESS', 'WARNING', 'DANGER')),
    title TEXT NOT NULL,
    message TEXT,
    target_page TEXT,
    target_url TEXT,
    related_table TEXT,
    related_id TEXT,
    status TEXT NOT NULL DEFAULT 'UNREAD'
        CHECK (status IN ('UNREAD', 'READ', 'ARCHIVED')),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_notifications_status_created
    ON admin_notifications(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_notifications_category_created
    ON admin_notifications(category, created_at DESC);
