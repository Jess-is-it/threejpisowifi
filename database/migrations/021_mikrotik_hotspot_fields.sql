ALTER TABLE mikrotik_routers
    ADD COLUMN IF NOT EXISTS hotspot_interface TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_address_pool TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_profile_name TEXT NOT NULL DEFAULT '3jcentralpisowifi-hotspot-profile',
    ADD COLUMN IF NOT EXISTS hotspot_server_name TEXT NOT NULL DEFAULT '3jcentralpisowifi-hotspot',
    ADD COLUMN IF NOT EXISTS hotspot_dns_name TEXT,
    ADD COLUMN IF NOT EXISTS hotspot_html_directory TEXT NOT NULL DEFAULT 'hotspot';

