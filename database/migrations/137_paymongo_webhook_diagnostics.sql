CREATE TABLE IF NOT EXISTS paymongo_webhook_diagnostics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_method TEXT NOT NULL,
    request_path TEXT NOT NULL,
    event_id TEXT,
    event_type TEXT,
    request_ip INET,
    cf_connecting_ip INET,
    x_forwarded_for TEXT,
    user_agent TEXT,
    cf_ray TEXT,
    content_type TEXT,
    content_length INTEGER,
    signature_present BOOLEAN NOT NULL DEFAULT false,
    signature_timestamp TEXT,
    body_sha256 TEXT,
    payload_json JSONB,
    header_names TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    headers_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_paymongo_webhook_diagnostics_created
    ON paymongo_webhook_diagnostics(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_paymongo_webhook_diagnostics_event
    ON paymongo_webhook_diagnostics(event_type, event_id);
