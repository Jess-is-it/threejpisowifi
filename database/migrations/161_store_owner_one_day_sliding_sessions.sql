UPDATE store_owner_sessions
SET expires_at = GREATEST(expires_at, now() + interval '1 day')
WHERE expires_at > now();
