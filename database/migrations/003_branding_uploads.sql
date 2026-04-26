UPDATE app_settings
SET value = jsonb_set(
    jsonb_set(
        value,
        '{branding,company_logo_url}',
        COALESCE(value #> '{branding,company_logo_url}', 'null'::jsonb),
        true
    ),
    '{branding,browser_logo_url}',
    COALESCE(value #> '{branding,browser_logo_url}', 'null'::jsonb),
    true
)
WHERE key = 'system';
