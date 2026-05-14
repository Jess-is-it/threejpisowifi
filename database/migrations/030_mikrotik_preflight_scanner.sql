CREATE TABLE IF NOT EXISTS mikrotik_preflight_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_id UUID REFERENCES mikrotik_routers(id) ON DELETE CASCADE,
    scan_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (scan_status IN ('PENDING', 'SUCCESS', 'FAILED')),
    router_identity TEXT,
    router_model TEXT,
    router_version TEXT,
    router_role_guess TEXT,
    recommended_deployment_mode TEXT,
    risk_level TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'BLOCKED')),
    raw_snapshot_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    sanitized_snapshot_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    findings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    conflicts_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendations_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    ai_summary TEXT,
    last_error TEXT,
    scanned_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mikrotik_preflight_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES mikrotik_preflight_scans(id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (category IN (
        'IDENTITY',
        'INTERFACE',
        'BRIDGE',
        'VLAN',
        'SUBNET',
        'POOL',
        'DHCP',
        'HOTSPOT',
        'PPPoE',
        'FIREWALL',
        'NAT',
        'ROUTING',
        'OSPF',
        'WIREGUARD',
        'RADIUS',
        'SYSTEM'
    )),
    severity TEXT NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'DANGER', 'BLOCKER')),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    related_object TEXT,
    recommendation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_scans_router_created
    ON mikrotik_preflight_scans(router_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_scans_status
    ON mikrotik_preflight_scans(scan_status);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_scans_risk
    ON mikrotik_preflight_scans(risk_level);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_findings_scan
    ON mikrotik_preflight_findings(scan_id);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_findings_category
    ON mikrotik_preflight_findings(category);

CREATE INDEX IF NOT EXISTS idx_mikrotik_preflight_findings_severity
    ON mikrotik_preflight_findings(severity);
