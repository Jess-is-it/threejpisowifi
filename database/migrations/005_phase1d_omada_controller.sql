CREATE TABLE IF NOT EXISTS omada_controller_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    controller_name TEXT NOT NULL DEFAULT 'Omada Controller',
    host TEXT NOT NULL DEFAULT '192.168.50.71',
    http_port INTEGER NOT NULL DEFAULT 8088,
    https_port INTEGER NOT NULL DEFAULT 8043,
    api_base_url TEXT NOT NULL DEFAULT 'https://192.168.50.71:8043',
    api_username TEXT,
    api_password_encrypted TEXT,
    api_token_encrypted TEXT,
    ssh_host TEXT NOT NULL DEFAULT '192.168.50.71',
    ssh_port INTEGER NOT NULL DEFAULT 22,
    ssh_username TEXT,
    ssh_auth_type TEXT NOT NULL DEFAULT 'PASSWORD',
    ssh_password_encrypted TEXT,
    ssh_private_key_encrypted TEXT,
    ssh_private_key_passphrase_encrypted TEXT,
    sudo_mode TEXT NOT NULL DEFAULT 'PASSWORDLESS',
    install_method TEXT NOT NULL DEFAULT 'DOCKER',
    network_mode TEXT NOT NULL DEFAULT 'bridge',
    docker_image TEXT NOT NULL DEFAULT 'mbentley/omada-controller:latest',
    install_status TEXT NOT NULL DEFAULT 'NOT_INSTALLED',
    last_detected_version TEXT,
    last_status_check_at TIMESTAMPTZ,
    last_error TEXT,
    checklist_progress JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (ssh_auth_type IN ('PASSWORD', 'PRIVATE_KEY')),
    CHECK (install_method IN ('DOCKER', 'NATIVE_PACKAGE')),
    CHECK (network_mode IN ('bridge', 'host')),
    CHECK (install_status IN ('NOT_INSTALLED', 'INSTALLING', 'INSTALLED', 'RUNNING', 'STOPPED', 'ERROR'))
);

CREATE TABLE IF NOT EXISTS omada_install_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    output_text TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CHECK (action IN ('DETECT', 'INSTALL', 'START', 'STOP', 'RESTART', 'STATUS', 'BACKUP', 'CHECK_PORTS', 'TEST_SSH', 'TEST_WEB')),
    CHECK (status IN ('RUNNING', 'SUCCESS', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS idx_omada_install_logs_created_at ON omada_install_logs(created_at DESC);

INSERT INTO omada_controller_settings (
    controller_name,
    host,
    http_port,
    https_port,
    api_base_url,
    ssh_host,
    ssh_port,
    install_method,
    install_status
)
SELECT
    'Omada Controller',
    '192.168.50.71',
    8088,
    8043,
    'https://192.168.50.71:8043',
    '192.168.50.71',
    22,
    'DOCKER',
    'NOT_INSTALLED'
WHERE NOT EXISTS (SELECT 1 FROM omada_controller_settings);
