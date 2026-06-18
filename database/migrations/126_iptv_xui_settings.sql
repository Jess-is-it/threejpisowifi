INSERT INTO app_settings(key, value)
VALUES (
    'iptv_xui',
    '{
      "enabled": false,
      "public_hostname": "tv.3jhotspot.com",
      "public_url": "https://tv.3jhotspot.com",
      "internal_web_url": "http://192.168.50.15:3000",
      "iptv_web_ssh_host": "192.168.50.15",
      "iptv_web_ssh_port": 22,
      "iptv_web_ssh_username": "root",
      "iptv_web_ssh_auth_type": "PASSWORD",
      "iptv_web_sudo_mode": "PASSWORDLESS",
      "xui_base_url": "http://10.100.100.100",
      "xui_server_host": "10.100.100.100",
      "xui_api_mode": "XUI_ADMIN_API",
      "xui_admin_username": "",
      "xui_test_username": "",
      "notes": "",
      "last_test_result": null,
      "last_tested_at": null,
      "last_xui_api_test_result": null,
      "last_xui_api_tested_at": null,
      "last_ssh_test_result": null,
      "last_ssh_tested_at": null
    }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
