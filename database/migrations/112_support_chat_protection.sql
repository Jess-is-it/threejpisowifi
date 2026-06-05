CREATE TABLE IF NOT EXISTS portal_support_message_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    normalized_mac TEXT,
    client_ip INET,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REMOVED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_support_message_blocks_user_active
    ON portal_support_message_blocks(user_id)
    WHERE status = 'ACTIVE' AND user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_portal_support_message_blocks_mac_active
    ON portal_support_message_blocks(normalized_mac)
    WHERE status = 'ACTIVE' AND normalized_mac IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_portal_support_message_blocks_ip_active
    ON portal_support_message_blocks(client_ip)
    WHERE status = 'ACTIVE' AND client_ip IS NOT NULL;

UPDATE app_settings
SET value = jsonb_set(
    value,
    '{support_chat_protection}',
    COALESCE(value->'support_chat_protection', '{
      "enabled": true,
      "max_continuous_messages": 5,
      "cooldown_seconds": 120,
      "blocked_device_max_bursts": 2,
      "permanently_block_blocked_devices": true
    }'::jsonb),
    true
),
updated_at = now()
WHERE key = 'system';
