UPDATE ap_deployments
SET adoption_device_account_username = NULL,
    adoption_device_account_fingerprint = NULL,
    adoption_device_account_applied = false,
    adoption_device_account_applied_at = NULL,
    updated_at = now()
WHERE adoption_device_account_username IS NOT NULL
   OR adoption_device_account_fingerprint IS NOT NULL
   OR adoption_device_account_applied = true
   OR adoption_device_account_applied_at IS NOT NULL;

UPDATE ap_deployment_configuration
SET device_account_username = NULL,
    device_account_password_encrypted = NULL,
    updated_at = now();
