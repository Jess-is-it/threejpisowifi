CREATE TABLE IF NOT EXISTS mikrotik_routers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    router_name TEXT NOT NULL,
    host TEXT NOT NULL,
    api_port INTEGER NOT NULL DEFAULT 8728 CHECK (api_port BETWEEN 1 AND 65535),
    use_tls BOOLEAN NOT NULL DEFAULT false,
    username TEXT,
    password_encrypted TEXT,
    account_privilege TEXT NOT NULL DEFAULT 'FULL' CHECK (account_privilege IN ('FULL', 'READ_ONLY')),
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'NOT_TESTED' CHECK (status IN ('NOT_TESTED', 'REACHABLE', 'AUTH_FAILED', 'UNREACHABLE', 'ERROR')),
    last_test_at TIMESTAMPTZ,
    last_error TEXT,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_routers_host ON mikrotik_routers(host);
CREATE INDEX IF NOT EXISTS idx_mikrotik_routers_status ON mikrotik_routers(status);

UPDATE captive_portal_settings
SET portal_mode = 'MIKROTIK', updated_at = now()
WHERE portal_mode = 'OMADA';

CREATE TABLE IF NOT EXISTS portal_design_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_name TEXT NOT NULL DEFAULT 'Default Portal Template',
    html_template TEXT NOT NULL,
    css_template TEXT NOT NULL DEFAULT '',
    updated_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO portal_design_templates(template_name, html_template, css_template)
SELECT
    'Default Portal Template',
    '<div class="portal-template-brand">{{brand}}</div>
{{voucher_form}}
{{help}}',
    ''
WHERE NOT EXISTS (SELECT 1 FROM portal_design_templates);
