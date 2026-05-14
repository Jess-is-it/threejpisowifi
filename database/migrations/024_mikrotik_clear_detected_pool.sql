UPDATE mikrotik_routers
SET hotspot_address_pool = NULL,
    updated_at = now()
WHERE hotspot_address_pool IS NOT NULL
  AND hotspot_address_pool <> ''
  AND configuration_step_status -> 'prepare_hotspot_profile' ->> 'status' = 'DETECTED';

