UPDATE captive_portal_settings
SET speed_indicator_json = COALESCE(speed_indicator_json, '{}'::jsonb)
  || '{
    "travel_speed": 1,
    "air_particles": 7,
    "smoke_particles": 5,
    "fire_intensity": 3
  }'::jsonb
WHERE speed_indicator_json IS NULL
   OR NOT (speed_indicator_json ? 'travel_speed')
   OR NOT (speed_indicator_json ? 'air_particles')
   OR NOT (speed_indicator_json ? 'smoke_particles')
   OR NOT (speed_indicator_json ? 'fire_intensity');
