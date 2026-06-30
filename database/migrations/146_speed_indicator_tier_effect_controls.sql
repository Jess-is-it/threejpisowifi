UPDATE captive_portal_settings
SET speed_indicator_json = jsonb_set(
  COALESCE(speed_indicator_json, '{}'::jsonb),
  '{tiers}',
  (
    SELECT jsonb_agg(
      (
        CASE COALESCE(tier->>'id', '')
          WHEN 'basic' THEN '{"travel_speed":1,"air_particles":4,"smoke_particles":4,"fire_intensity":2}'::jsonb
          WHEN 'steady' THEN '{"travel_speed":2,"air_particles":7,"smoke_particles":5,"fire_intensity":3}'::jsonb
          WHEN 'fast' THEN '{"travel_speed":3,"air_particles":10,"smoke_particles":7,"fire_intensity":5}'::jsonb
          WHEN 'rocket' THEN '{"travel_speed":5,"air_particles":14,"smoke_particles":10,"fire_intensity":8}'::jsonb
          ELSE '{"travel_speed":2,"air_particles":7,"smoke_particles":5,"fire_intensity":3}'::jsonb
        END
      ) || tier
      ORDER BY ord
    )
    FROM jsonb_array_elements(COALESCE(speed_indicator_json->'tiers', '[]'::jsonb)) WITH ORDINALITY AS item(tier, ord)
  )
)
WHERE jsonb_typeof(speed_indicator_json->'tiers') = 'array'
  AND EXISTS (
    SELECT 1
    FROM jsonb_array_elements(speed_indicator_json->'tiers') AS item(tier)
    WHERE NOT (tier ? 'travel_speed')
       OR NOT (tier ? 'air_particles')
       OR NOT (tier ? 'smoke_particles')
       OR NOT (tier ? 'fire_intensity')
  );

UPDATE captive_portal_settings
SET speed_indicator_json = COALESCE(speed_indicator_json, '{}'::jsonb)
  - 'travel_speed'
  - 'air_particles'
  - 'smoke_particles'
  - 'fire_intensity'
WHERE speed_indicator_json ? 'travel_speed'
   OR speed_indicator_json ? 'air_particles'
   OR speed_indicator_json ? 'smoke_particles'
   OR speed_indicator_json ? 'fire_intensity';
