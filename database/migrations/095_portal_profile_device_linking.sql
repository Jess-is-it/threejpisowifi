CREATE TABLE IF NOT EXISTS portal_device_link_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  owner_profile_id UUID REFERENCES portal_customer_profiles(id) ON DELETE CASCADE,
  owner_portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
  target_portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'USED', 'EXPIRED', 'FAILED')),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_device_link_codes_owner_created
  ON portal_device_link_codes(owner_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_portal_device_link_codes_hash_status
  ON portal_device_link_codes(code_hash, status, expires_at DESC);

ALTER TABLE portal_events DROP CONSTRAINT IF EXISTS portal_events_event_type_check;
ALTER TABLE portal_events
  ADD CONSTRAINT portal_events_event_type_check
  CHECK (event_type IS NOT NULL AND event_type ~ '^[A-Z0-9_]+$');
