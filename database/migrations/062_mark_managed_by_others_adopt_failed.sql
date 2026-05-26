-- Omada "Managed by Others" means this controller is not managing the AP.
-- Keep the row visible in List of APs as an adoption failure so the operator can retry or remove it.
UPDATE ap_deployments
SET deployment_status = 'ADOPT_FAILED',
    configuration_status = 'PENDING',
    configuration_error = NULL,
    configuration_components_json = '{}'::jsonb,
    configured_at = NULL,
    last_error = 'Omada reports this AP is managed by another controller/account. Factory reset it or use the correct adoption credentials, then adopt again.',
    updated_at = now()
WHERE deployment_status <> 'DELETED'
  AND (
    lower(coalesce(last_omada_status, '')) LIKE '%managed by others%'
    OR raw_omada->>'status' IN ('26', '27', '30')
    OR raw_omada->>'statusCategory' = '3'
  );
