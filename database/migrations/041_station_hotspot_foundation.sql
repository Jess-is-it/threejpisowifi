ALTER TABLE mikrotik_stations
    ADD COLUMN IF NOT EXISTS create_hotspot_profile BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS create_hotspot_server BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS create_walled_garden BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS hotspot_profile_name TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_html_directory TEXT NOT NULL DEFAULT 'hotspot';

UPDATE mikrotik_stations
SET create_hotspot_profile = COALESCE(create_hotspot_profile, TRUE),
    create_hotspot_server = COALESCE(create_hotspot_server, TRUE),
    create_walled_garden = COALESCE(create_walled_garden, TRUE),
    hotspot_profile_name = COALESCE(NULLIF(btrim(hotspot_profile_name), ''), 'PROFILE-3J-HOTSPOT-V' || vlan_id::TEXT),
    hotspot_html_directory = COALESCE(NULLIF(btrim(hotspot_html_directory), ''), 'hotspot');
