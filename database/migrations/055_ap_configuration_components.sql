ALTER TABLE ap_deployments
    ADD COLUMN IF NOT EXISTS configuration_components_json jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_ap_deployments_configuration_components
    ON ap_deployments USING gin (configuration_components_json);
