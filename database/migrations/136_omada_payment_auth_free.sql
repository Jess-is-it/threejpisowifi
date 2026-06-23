INSERT INTO app_settings(key, value, updated_at)
VALUES (
  'omada_payment_auth_free',
  '{
    "enabled": true,
    "browser_transfer_required": true,
    "grant_timeout_seconds": 120,
    "daily_attempt_limit": 5,
    "cooldown_seconds": 60,
    "abuse_block_hours": 24,
    "block_online_payment_on_abuse": true,
    "notes": "Temporarily places a client MAC in Omada Authentication-Free Client only while the customer completes PayMongo checkout in Chrome/Safari."
  }'::jsonb,
  now()
)
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS omada_payment_auth_free_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  public_grant_id text NOT NULL UNIQUE,
  payment_order_id uuid REFERENCES payment_orders(id) ON DELETE SET NULL,
  portal_session_id uuid REFERENCES portal_sessions(id) ON DELETE SET NULL,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  site_id text,
  site_name text,
  client_mac text,
  client_ip inet,
  device_token_hash text,
  profile_name text,
  profile_contact_number text,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'EXPIRED', 'REMOVED', 'CANCELLED', 'FAILED', 'REMOVE_FAILED', 'GRANT_SKIPPED', 'ABUSE_BLOCKED')),
  reason text NOT NULL DEFAULT 'PAYMONGO_CHECKOUT',
  granted_at timestamptz,
  expires_at timestamptz,
  removed_at timestamptz,
  omada_request_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  omada_response_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  removal_response_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_omada_payment_auth_free_grants_status_expires
  ON omada_payment_auth_free_grants(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_omada_payment_auth_free_grants_order
  ON omada_payment_auth_free_grants(payment_order_id);

CREATE INDEX IF NOT EXISTS idx_omada_payment_auth_free_grants_session
  ON omada_payment_auth_free_grants(portal_session_id);

CREATE INDEX IF NOT EXISTS idx_omada_payment_auth_free_grants_user
  ON omada_payment_auth_free_grants(user_id);

CREATE INDEX IF NOT EXISTS idx_omada_payment_auth_free_grants_mac
  ON omada_payment_auth_free_grants(client_mac);

CREATE TABLE IF NOT EXISTS omada_payment_auth_free_abuse_blocks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  portal_session_id uuid REFERENCES portal_sessions(id) ON DELETE SET NULL,
  client_mac text,
  device_token_hash text,
  profile_name text,
  profile_contact_number text,
  attempts_today integer NOT NULL DEFAULT 0,
  reason text NOT NULL DEFAULT 'DAILY_LIMIT',
  block_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_omada_payment_auth_free_abuse_blocks_until
  ON omada_payment_auth_free_abuse_blocks(block_until);

CREATE INDEX IF NOT EXISTS idx_omada_payment_auth_free_abuse_blocks_user
  ON omada_payment_auth_free_abuse_blocks(user_id);

CREATE INDEX IF NOT EXISTS idx_omada_payment_auth_free_abuse_blocks_mac
  ON omada_payment_auth_free_abuse_blocks(client_mac);
