ALTER TABLE sessions ADD COLUMN IF NOT EXISTS acct_unique_session_id TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS acct_session_time INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE sessions SET status = upper(status) WHERE status IN ('active', 'stopped', 'stale');

CREATE INDEX IF NOT EXISTS idx_sessions_status_last_update ON sessions(status, last_update_time DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_acct_session ON sessions(username, acct_session_id, calling_station_id);

CREATE TABLE IF NOT EXISTS radius_accounting_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT,
    acct_status_type TEXT,
    acct_session_id TEXT,
    nas_ip INET,
    nas_identifier TEXT,
    calling_station_id TEXT,
    framed_ip_address INET,
    acct_session_time INTEGER NOT NULL DEFAULT 0,
    input_octets BIGINT NOT NULL DEFAULT 0,
    output_octets BIGINT NOT NULL DEFAULT 0,
    raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    result TEXT NOT NULL,
    diagnostic_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_radius_accounting_logs_created_at ON radius_accounting_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_radius_accounting_logs_session ON radius_accounting_logs(username, acct_session_id, created_at DESC);
