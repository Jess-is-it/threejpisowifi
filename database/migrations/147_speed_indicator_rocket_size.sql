UPDATE captive_portal_settings
SET speed_indicator_json = jsonb_set(
  COALESCE(speed_indicator_json, '{}'::jsonb),
  '{tiers}',
  (
    SELECT jsonb_agg(
      (
        CASE COALESCE(tier->>'id', '')
          WHEN 'basic' THEN '{"rocket_size":1}'::jsonb
          WHEN 'steady' THEN '{"rocket_size":2}'::jsonb
          WHEN 'fast' THEN '{"rocket_size":3}'::jsonb
          WHEN 'rocket' THEN '{"rocket_size":5}'::jsonb
          ELSE '{"rocket_size":2}'::jsonb
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
    WHERE NOT (tier ? 'rocket_size')
  );
