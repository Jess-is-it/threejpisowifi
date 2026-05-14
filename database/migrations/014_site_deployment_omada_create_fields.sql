ALTER TABLE site_deployments ADD COLUMN IF NOT EXISTS application_scenario TEXT;
ALTER TABLE site_deployments ADD COLUMN IF NOT EXISTS country_region TEXT;
ALTER TABLE site_deployments ADD COLUMN IF NOT EXISTS time_zone TEXT;
