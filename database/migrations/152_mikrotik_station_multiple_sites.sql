CREATE TABLE IF NOT EXISTS mikrotik_station_sites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    station_id UUID NOT NULL REFERENCES mikrotik_stations(id) ON DELETE CASCADE,
    site_deployment_id UUID REFERENCES site_deployments(id) ON DELETE SET NULL,
    omada_site_id TEXT,
    omada_site_name TEXT,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    vlan_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mikrotik_station_sites_station
    ON mikrotik_station_sites(station_id, is_primary DESC, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_mikrotik_station_sites_site_deployment
    ON mikrotik_station_sites(site_deployment_id)
    WHERE site_deployment_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mikrotik_station_sites_station_site
    ON mikrotik_station_sites(station_id, site_deployment_id)
    WHERE site_deployment_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mikrotik_station_sites_station_omada_id
    ON mikrotik_station_sites(station_id, omada_site_id)
    WHERE omada_site_id IS NOT NULL AND btrim(omada_site_id) <> '';

CREATE INDEX IF NOT EXISTS idx_mikrotik_station_sites_omada_id
    ON mikrotik_station_sites(omada_site_id)
    WHERE omada_site_id IS NOT NULL AND btrim(omada_site_id) <> '';

INSERT INTO mikrotik_station_sites(
    station_id,
    site_deployment_id,
    omada_site_id,
    omada_site_name,
    is_primary,
    vlan_confirmed,
    created_by_admin_id,
    created_at,
    updated_at
)
SELECT
    s.id,
    sd.id,
    NULLIF(btrim(s.omada_site_id), ''),
    NULLIF(btrim(s.omada_site_name), ''),
    TRUE,
    COALESCE(s.omada_site_vlan_confirmed, FALSE),
    s.omada_site_bound_by_admin_id,
    COALESCE(s.omada_site_bound_at, s.created_at, now()),
    now()
FROM mikrotik_stations s
LEFT JOIN site_deployments sd
    ON (
        NULLIF(btrim(s.omada_site_id), '') IS NOT NULL
        AND sd.omada_site_id = NULLIF(btrim(s.omada_site_id), '')
    )
    OR (
        NULLIF(btrim(s.omada_site_name), '') IS NOT NULL
        AND lower(sd.site_name) = lower(NULLIF(btrim(s.omada_site_name), ''))
    )
WHERE s.status <> 'ARCHIVED'
  AND (
      NULLIF(btrim(s.omada_site_id), '') IS NOT NULL
      OR NULLIF(btrim(s.omada_site_name), '') IS NOT NULL
  )
ON CONFLICT DO NOTHING;
