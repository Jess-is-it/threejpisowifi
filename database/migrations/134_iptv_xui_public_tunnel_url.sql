UPDATE app_settings
SET value = value || jsonb_build_object(
        'xui_public_url', 'https://xui.3jhotspot.com',
        'xui_public_tunnel_token_encrypted', NULL
    ),
    updated_at = now()
WHERE key = 'iptv_xui'
  AND (
      NOT (value ? 'xui_public_url')
      OR NOT (value ? 'xui_public_tunnel_token_encrypted')
  );
