ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS pwa_name TEXT NOT NULL DEFAULT '3J WiFi Portal',
    ADD COLUMN IF NOT EXISTS pwa_short_name TEXT NOT NULL DEFAULT '3J WiFi',
    ADD COLUMN IF NOT EXISTS pwa_description TEXT NOT NULL DEFAULT '3J WiFi customer portal for WiFi passes, time alerts, and support.',
    ADD COLUMN IF NOT EXISTS pwa_theme_color TEXT NOT NULL DEFAULT '#ff3838',
    ADD COLUMN IF NOT EXISTS pwa_background_color TEXT NOT NULL DEFAULT '#f8fafc',
    ADD COLUMN IF NOT EXISTS pwa_icon_url TEXT,
    ADD COLUMN IF NOT EXISTS pwa_display_mode TEXT NOT NULL DEFAULT 'standalone',
    ADD COLUMN IF NOT EXISTS pwa_install_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS pwa_gift_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS pwa_gift_duration_seconds INTEGER NOT NULL DEFAULT 3600,
    ADD COLUMN IF NOT EXISTS pwa_gift_title TEXT NOT NULL DEFAULT 'PWA Install Gift',
    ADD COLUMN IF NOT EXISTS pwa_gift_available_message TEXT NOT NULL DEFAULT 'Home Screen app gift is ready.',
    ADD COLUMN IF NOT EXISTS pwa_gift_claim_message TEXT NOT NULL DEFAULT 'PWA install gift added to My WiFi Bag.',
    ADD COLUMN IF NOT EXISTS pwa_install_guide_message TEXT NOT NULL DEFAULT 'Install the 3J WiFi portal as a Home Screen app for faster access and better phone notification support.';

ALTER TABLE captive_portal_settings
    DROP CONSTRAINT IF EXISTS captive_portal_settings_pwa_gift_duration_positive;

ALTER TABLE captive_portal_settings
    ADD CONSTRAINT captive_portal_settings_pwa_gift_duration_positive
    CHECK (pwa_gift_duration_seconds > 0);

CREATE TABLE IF NOT EXISTS portal_pwa_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    profile_id UUID REFERENCES portal_customer_profiles(id) ON DELETE SET NULL,
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    device_token_hash TEXT,
    event_type TEXT NOT NULL CHECK (event_type IN ('INSTALL_PROMPT_ACCEPTED', 'INSTALL_PROMPT_DISMISSED', 'APP_INSTALLED', 'STANDALONE_OPEN')),
    display_mode TEXT,
    platform TEXT,
    browser TEXT,
    user_agent TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_pwa_events_created
    ON portal_pwa_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_portal_pwa_events_user
    ON portal_pwa_events(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_portal_pwa_events_profile
    ON portal_pwa_events(profile_id, created_at DESC);

CREATE TABLE IF NOT EXISTS portal_pwa_gift_claims (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile_id UUID REFERENCES portal_customer_profiles(id) ON DELETE SET NULL,
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    event_id UUID REFERENCES portal_pwa_events(id) ON DELETE SET NULL,
    voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
    bag_item_id UUID REFERENCES customer_bag_items(id) ON DELETE SET NULL,
    device_token_hash TEXT,
    gift_title TEXT NOT NULL,
    gift_duration_seconds INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_portal_pwa_gift_claims_created
    ON portal_pwa_gift_claims(created_at DESC);

ALTER TABLE portal_events DROP CONSTRAINT IF EXISTS portal_events_event_type_check;
ALTER TABLE portal_events
    ADD CONSTRAINT portal_events_event_type_check
    CHECK (event_type IS NOT NULL AND event_type ~ '^[A-Z0-9_]+$');
