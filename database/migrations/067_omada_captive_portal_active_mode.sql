UPDATE captive_portal_settings
SET portal_mode = 'OMADA',
    updated_at = now()
WHERE portal_mode = 'MIKROTIK';
