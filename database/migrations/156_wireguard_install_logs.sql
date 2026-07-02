CREATE TABLE IF NOT EXISTS wireguard_install_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    current_step TEXT,
    output_text TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CHECK (action IN ('DETECT', 'INSTALL', 'START', 'STOP', 'RESTART', 'STATUS', 'TEST_SSH')),
    CHECK (status IN ('RUNNING', 'SUCCESS', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS idx_wireguard_install_logs_created_at ON wireguard_install_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wireguard_install_logs_running ON wireguard_install_logs(status, created_at DESC);
