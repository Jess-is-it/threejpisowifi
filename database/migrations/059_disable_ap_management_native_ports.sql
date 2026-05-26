-- Native/untagged AP-facing AP management ports are disabled for now.
-- Operators will manually enable AP management VLAN on APs before station deployment.
UPDATE mikrotik_ap_management_routers
SET untagged_ports = NULL,
    updated_at = now()
WHERE untagged_ports IS NOT NULL
  AND btrim(untagged_ports) <> '';
