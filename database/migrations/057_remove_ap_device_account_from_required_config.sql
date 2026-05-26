UPDATE ap_deployments
SET configuration_components_json = configuration_components_json - 'device_account',
    configuration_error = NULLIF(regexp_replace(coalesce(configuration_error, ''), 'Device account:[^|]*(\\|\\s*)?', '', 'gi'), '')
WHERE configuration_components_json ? 'device_account';

UPDATE ap_deployment_configuration
SET device_account_username = NULL,
    device_account_password_encrypted = NULL,
    updated_at = now();
