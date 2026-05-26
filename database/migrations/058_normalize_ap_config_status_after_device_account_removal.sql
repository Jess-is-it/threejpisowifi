UPDATE ap_deployments
SET configuration_status = 'APPLIED',
    configuration_error = NULL,
    configured_at = COALESCE(configured_at, updated_at, now()),
    updated_at = now()
WHERE configuration_components_json <> '{}'::jsonb
  AND EXISTS (
      SELECT 1
      FROM jsonb_each(configuration_components_json) AS component(key, value)
      WHERE COALESCE((component.value->>'required')::boolean, true)
  )
  AND NOT EXISTS (
      SELECT 1
      FROM jsonb_each(configuration_components_json) AS component(key, value)
      WHERE COALESCE((component.value->>'required')::boolean, true)
        AND upper(coalesce(component.value->>'status', 'PENDING')) <> 'SUCCESS'
  );
