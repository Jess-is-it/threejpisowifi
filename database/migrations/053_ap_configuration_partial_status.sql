DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ap_deployments_configuration_status_check'
    ) THEN
        ALTER TABLE ap_deployments DROP CONSTRAINT ap_deployments_configuration_status_check;
    END IF;
END $$;

ALTER TABLE ap_deployments
    ADD CONSTRAINT ap_deployments_configuration_status_check
    CHECK (configuration_status IN ('NOT_CONFIGURED', 'PENDING', 'APPLYING', 'APPLIED', 'FAILED', 'PARTIAL'));

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ap_configuration_logs_status_check'
    ) THEN
        ALTER TABLE ap_configuration_logs DROP CONSTRAINT ap_configuration_logs_status_check;
    END IF;
END $$;

ALTER TABLE ap_configuration_logs
    ADD CONSTRAINT ap_configuration_logs_status_check
    CHECK (status IN ('SUCCESS', 'FAILED', 'SKIPPED', 'PARTIAL'));
