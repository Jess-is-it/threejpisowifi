UPDATE ap_deployment_configuration
SET auto_apply_enabled = false,
    updated_at = now()
WHERE auto_apply_enabled IS DISTINCT FROM false;
