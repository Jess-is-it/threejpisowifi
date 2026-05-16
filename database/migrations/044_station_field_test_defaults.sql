UPDATE mikrotik_stations
SET hotspot_server_name = COALESCE(NULLIF(btrim(hotspot_server_name), ''), 'HS-3J-HOTSPOT-V' || vlan_id::text),
    portal_url = COALESCE(
        NULLIF(btrim(portal_url), ''),
        (SELECT COALESCE(portal_url_staging, portal_url_production, 'http://192.168.50.70:8080/portal')
         FROM captive_portal_settings
         ORDER BY updated_at DESC
         LIMIT 1),
        'http://192.168.50.70:8080/portal'
    ),
    updated_at = now()
WHERE status <> 'ARCHIVED'
  AND (
    hotspot_server_name IS NULL
    OR btrim(hotspot_server_name) = ''
    OR portal_url IS NULL
    OR btrim(portal_url) = ''
  );
