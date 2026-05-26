-- Omada controller IDs are runtime discovery values and change after
-- reinstall/restore. Do not persist a stale controller ID in app settings.
UPDATE omada_api_settings
SET controller_id = NULL,
    updated_at = now()
WHERE controller_id IS NOT NULL;
