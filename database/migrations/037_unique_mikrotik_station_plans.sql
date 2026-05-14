WITH ranked_stations AS (
    SELECT
        id,
        row_number() OVER (
            PARTITION BY lower(btrim(station_name))
            ORDER BY updated_at DESC, created_at DESC, id DESC
        ) AS duplicate_rank
    FROM mikrotik_stations
    WHERE status <> 'ARCHIVED'
)
UPDATE mikrotik_stations
SET status = 'ARCHIVED',
    updated_at = now()
WHERE id IN (
    SELECT id
    FROM ranked_stations
    WHERE duplicate_rank > 1
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_mikrotik_stations_active_station_name
    ON mikrotik_stations (lower(btrim(station_name)))
    WHERE status <> 'ARCHIVED';
