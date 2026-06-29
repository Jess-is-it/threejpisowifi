UPDATE app_settings
SET value = value || '{"post_payment_cleanup_delay_seconds": 20}'::jsonb,
    updated_at = now()
WHERE key = 'omada_payment_auth_free'
  AND NOT (value ? 'post_payment_cleanup_delay_seconds');

ALTER TABLE omada_payment_auth_free_grants
  DROP CONSTRAINT IF EXISTS omada_payment_auth_free_grants_status_check;

ALTER TABLE omada_payment_auth_free_grants
  ADD CONSTRAINT omada_payment_auth_free_grants_status_check
  CHECK (status IN (
    'PENDING',
    'ACTIVE',
    'PAID_GRACE',
    'EXPIRED',
    'REMOVED',
    'CANCELLED',
    'FAILED',
    'REMOVE_FAILED',
    'GRANT_SKIPPED',
    'ABUSE_BLOCKED'
  ));
