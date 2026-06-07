ALTER TABLE captive_portal_settings
  ALTER COLUMN bag_activation_overlap_seconds SET DEFAULT 60;

UPDATE captive_portal_settings
SET bag_activation_overlap_seconds = 60,
    updated_at = now()
WHERE COALESCE(bag_activation_overlap_seconds, 0) < 60;
