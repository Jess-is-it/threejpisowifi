-- Store owner portal sessions must be fixed-length 4 hour sessions.
-- Older builds created some longer-lived rows, so cap them once during migration.
UPDATE store_owner_sessions
SET expires_at = LEAST(expires_at, created_at + interval '4 hours')
WHERE expires_at > created_at + interval '4 hours';

CREATE INDEX IF NOT EXISTS idx_store_owner_sessions_token_active
  ON store_owner_sessions(token_hash, created_at, expires_at);
