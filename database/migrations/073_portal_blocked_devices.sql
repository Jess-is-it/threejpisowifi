CREATE TABLE IF NOT EXISTS portal_blocked_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    normalized_mac TEXT,
    client_ip INET,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REMOVED')),
    blocked_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_portal_blocked_devices_active_mac
    ON portal_blocked_devices(normalized_mac)
    WHERE status = 'ACTIVE' AND normalized_mac IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_portal_blocked_devices_active_ip
    ON portal_blocked_devices(client_ip)
    WHERE status = 'ACTIVE' AND client_ip IS NOT NULL;
