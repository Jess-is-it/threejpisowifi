ALTER TABLE omada_install_logs
    DROP CONSTRAINT IF EXISTS omada_install_logs_action_check;

ALTER TABLE omada_install_logs
    ADD CONSTRAINT omada_install_logs_action_check
    CHECK (action IN ('DETECT', 'INSTALL', 'START', 'STOP', 'RESTART', 'STATUS', 'BACKUP', 'CHECK_PORTS', 'TEST_SSH', 'TEST_WEB', 'APPLY_HOST_NETWORK'));
