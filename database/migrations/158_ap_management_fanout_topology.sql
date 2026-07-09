ALTER TABLE mikrotik_ap_management_routers
    ADD COLUMN IF NOT EXISTS topology_role TEXT,
    ADD COLUMN IF NOT EXISTS parent_router_id UUID REFERENCES mikrotik_routers(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS branch_label TEXT,
    ADD COLUMN IF NOT EXISTS station_id UUID REFERENCES mikrotik_stations(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS upstream_ports TEXT,
    ADD COLUMN IF NOT EXISTS ap_path_ports TEXT;

UPDATE mikrotik_ap_management_routers
SET topology_role = CASE
        WHEN sequence_order = 0 OR router_role = 'ROOT_GATEWAY' THEN 'CENTRAL_GATEWAY'
        WHEN sequence_order = 1 THEN 'CORE_TRUNK'
        ELSE 'SUBSTATION_BRANCH'
    END,
    updated_at = now()
WHERE topology_role IS NULL OR btrim(topology_role) = '';

UPDATE mikrotik_ap_management_routers branch
SET parent_router_id = core.router_id,
    updated_at = now()
FROM mikrotik_ap_management_routers core
WHERE branch.config_id = core.config_id
  AND branch.topology_role = 'SUBSTATION_BRANCH'
  AND core.topology_role = 'CORE_TRUNK'
  AND branch.parent_router_id IS NULL;
