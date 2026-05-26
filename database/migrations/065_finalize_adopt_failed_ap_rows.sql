UPDATE ap_deployments
SET deployment_status = 'ADOPT_FAILED',
    last_error = COALESCE(NULLIF(last_error, ''), 'Omada reported adoption failed.'),
    updated_at = now()
WHERE deployment_status = 'ADOPTING'
  AND (
    lower(coalesce(last_omada_status, '')) LIKE '%adopt failed%'
    OR lower(coalesce(last_omada_status, '')) LIKE '%failed%'
    OR lower(coalesce(last_omada_status, '')) LIKE '%managed by others%'
  );
