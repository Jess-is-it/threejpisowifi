UPDATE mikrotik_routers
SET hotspot_interface = NULL,
    updated_at = now()
WHERE hotspot_interface IS NOT NULL
  AND configuration_step_status -> 'prepare_hotspot_profile' ->> 'status' = 'DETECTED'
  AND lower(hotspot_interface) ~ '(management|mgmt|wan|uplink|internet)';

