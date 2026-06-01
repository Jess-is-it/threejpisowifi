INSERT INTO app_settings(key, value)
VALUES (
    'a2p_messaging',
    '{
      "enabled": false,
      "provider": "SMART_MESSAGING_SUITE",
      "base_url": "https://enterprise.messagingsuite.smart.com.ph",
      "send_path": "/cgphttp/servlet/sendmsg",
      "query_path": "/cgphttp/servlet/querymsg",
      "cancel_path": "/cgphttp/servlet/cancelmsg",
      "start_batch_path": "/cgphttp/servlet/startbatch",
      "send_batch_path": "/cgphttp/servlet/sendbatch",
      "credits_path": "/cgpapi/service1/credits",
      "auth_method": "API_KEY_HEADERS",
      "api_id": "",
      "default_source": "",
      "source_addresses": ["3JXENTRONET", "3J BILL", "3J ALERT", "3J PROMO", "3J FibrWIFI"],
      "registered_delivery": true,
      "monthly_credit_limit": null,
      "monthly_reset_day": 1,
      "notes": ""
    }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
