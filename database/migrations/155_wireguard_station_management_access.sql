UPDATE mikrotik_stations
SET wireguard_allowed_addresses = CASE
    WHEN wireguard_allowed_addresses IS NULL OR btrim(wireguard_allowed_addresses) = ''
      THEN '192.168.50.0/24,10.250.0.1/32'
    WHEN wireguard_allowed_addresses LIKE '%10.250.0.1/32%'
      THEN wireguard_allowed_addresses
    ELSE wireguard_allowed_addresses || ',10.250.0.1/32'
  END,
  updated_at = now()
WHERE status <> 'ARCHIVED'
  AND wireguard_enabled = TRUE;
