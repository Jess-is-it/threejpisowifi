UPDATE app_settings
SET value = jsonb_set(value, '{branding,portal_subtitle}', to_jsonb('Buy a WiFi pass to connect'::text), true)
WHERE key = 'system'
  AND value #>> '{branding,portal_subtitle}' = 'Enter your voucher to connect';

UPDATE app_settings
SET value = jsonb_set(value, '{branding,portal_welcome_message}', to_jsonb('Welcome to 3J WiFi. Buy a WiFi pass or claim an optional voucher to start using the internet.'::text), true)
WHERE key = 'system'
  AND value #>> '{branding,portal_welcome_message}' = 'Welcome to 3J WiFi. Please enter your voucher code to start using the internet.';

UPDATE app_settings
SET value = jsonb_set(value, '{branding,portal_support_text}', to_jsonb('Need help? Ask the nearest operator.'::text), true)
WHERE key = 'system'
  AND value #>> '{branding,portal_support_text}' = 'Need a voucher? Ask the nearest vendo/operator.';
