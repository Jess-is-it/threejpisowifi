UPDATE mikrotik_routers
SET configuration_status = 'NOT_REVIEWED',
    updated_at = now()
WHERE configuration_status = 'REVIEWED';

