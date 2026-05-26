ALTER TABLE ap_deployments
    DROP CONSTRAINT IF EXISTS ap_deployments_deployment_status_check;

ALTER TABLE ap_deployments
    ADD CONSTRAINT ap_deployments_deployment_status_check
    CHECK (deployment_status IN ('PENDING', 'ADOPTING', 'CONNECTED', 'ADOPT_FAILED', 'DISCONNECTED', 'DELETED'));
