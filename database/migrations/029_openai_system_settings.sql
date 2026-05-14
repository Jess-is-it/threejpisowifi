INSERT INTO app_settings(key, value)
VALUES (
    'openai',
    '{
      "selected_model": "gpt-5.4-mini",
      "reasoning_effort": "medium",
      "organization_id": "",
      "project_id": ""
    }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
