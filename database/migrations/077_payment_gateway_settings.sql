INSERT INTO app_settings(key, value)
VALUES (
    'payment_gateway',
    '{
      "enabled": false,
      "provider": "PAYMONGO",
      "mode": "TEST",
      "api_base_url": "https://api.paymongo.com/v1",
      "credentials": {
        "TEST": {},
        "LIVE": {}
      },
      "currency": "PHP",
      "enabled_payment_methods": ["gcash"],
      "success_url": "http://192.168.50.70/portal?payment=success",
      "cancel_url": "http://192.168.50.70/portal?payment=cancelled",
      "notes": ""
    }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
