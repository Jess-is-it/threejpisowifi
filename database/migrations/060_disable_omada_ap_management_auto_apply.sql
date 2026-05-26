-- Device-side AP management VLAN assignment is manual for now.
-- Keep MikroTik AP Management transport records, but remove the old Omada AP
-- management component from AP implementation checklists so progress reflects
-- only managed SSIDs and SSID customer VLAN.
UPDATE ap_deployments
SET configuration_components_json = configuration_components_json - 'ap_management_vlan',
    updated_at = now()
WHERE configuration_components_json ? 'ap_management_vlan';
