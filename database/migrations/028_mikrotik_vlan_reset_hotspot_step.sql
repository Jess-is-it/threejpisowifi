UPDATE mikrotik_routers
SET configuration_step_status = configuration_step_status - 'prepare_hotspot_profile',
    configuration_status = 'NOT_REVIEWED',
    updated_at = now()
WHERE hotspot_vlan_id IS NULL
   OR hotspot_vlan_parent_interface IS NULL
   OR trim(hotspot_vlan_parent_interface) = '';
