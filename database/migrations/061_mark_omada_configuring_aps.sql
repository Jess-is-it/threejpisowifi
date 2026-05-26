-- Omada status code 11 is a configuring/syncing AP, not a fully connected AP.
-- Existing rows seen in this state should not keep an old APPLIED checklist.
ALTER TABLE ap_deployments
    DROP CONSTRAINT IF EXISTS ap_deployments_deployment_status_check;

ALTER TABLE ap_deployments
    ADD CONSTRAINT ap_deployments_deployment_status_check
    CHECK (deployment_status IN ('PENDING', 'ADOPTING', 'CONFIGURING', 'CONNECTED', 'ADOPT_FAILED', 'DISCONNECTED', 'DELETED'));

UPDATE ap_deployments
SET deployment_status = 'CONFIGURING',
    configuration_status = 'PENDING',
    configuration_error = NULL,
    configuration_components_json = '{}'::jsonb,
    configured_at = NULL,
    updated_at = now()
WHERE raw_omada->>'status' IN ('10', '11', '12', '13')
  AND deployment_status <> 'DELETED';
