ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS no_internet_headline TEXT NOT NULL DEFAULT 'No Internet Detected',
    ADD COLUMN IF NOT EXISTS no_internet_avatar_disconnected_url TEXT,
    ADD COLUMN IF NOT EXISTS no_internet_avatar_connected_url TEXT,
    ADD COLUMN IF NOT EXISTS marketing_sms_consent_text TEXT NOT NULL DEFAULT 'I agree to receive Threej Internet & CCTV promos, service updates, and important account messages by SMS. I can ask the operator to stop promotional messages anytime.';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS full_name TEXT,
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS marketing_sms_consent BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS profile_verified_at TIMESTAMPTZ;

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS customer_name TEXT,
    ADD COLUMN IF NOT EXISTS customer_email TEXT,
    ADD COLUMN IF NOT EXISTS customer_contact_number TEXT;

CREATE TABLE IF NOT EXISTS portal_customer_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    email TEXT,
    contact_number TEXT NOT NULL,
    normalized_contact TEXT NOT NULL UNIQUE,
    contact_verified_at TIMESTAMPTZ,
    terms_accepted_at TIMESTAMPTZ,
    marketing_sms_consent BOOLEAN NOT NULL DEFAULT false,
    welcome_voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
    welcome_gift_status TEXT NOT NULL DEFAULT 'NONE' CHECK (welcome_gift_status IN ('NONE', 'AVAILABLE', 'REDEEMED')),
    welcome_gift_created_at TIMESTAMPTZ,
    welcome_gift_redeemed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_customer_profiles_user
    ON portal_customer_profiles(user_id);

CREATE TABLE IF NOT EXISTS portal_contact_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('PROFILE', 'MISSING_TIME')),
    contact_number TEXT NOT NULL,
    normalized_contact TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'FAILED')),
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_contact_verifications_lookup
    ON portal_contact_verifications(normalized_contact, purpose, status, created_at DESC);

CREATE TABLE IF NOT EXISTS portal_support_conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_conversation_id TEXT UNIQUE NOT NULL,
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    customer_name TEXT,
    contact_number TEXT,
    email TEXT,
    subject TEXT NOT NULL DEFAULT 'Customer message',
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'PENDING_ADMIN', 'PENDING_CUSTOMER', 'CLOSED')),
    priority TEXT NOT NULL DEFAULT 'NORMAL' CHECK (priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')),
    last_message_at TIMESTAMPTZ,
    unread_admin_count INTEGER NOT NULL DEFAULT 0,
    unread_customer_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portal_support_conversations_status
    ON portal_support_conversations(status, last_message_at DESC NULLS LAST);

CREATE TABLE IF NOT EXISTS portal_support_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES portal_support_conversations(id) ON DELETE CASCADE,
    sender_type TEXT NOT NULL CHECK (sender_type IN ('CUSTOMER', 'ADMIN', 'SYSTEM')),
    admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    message_text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_portal_support_messages_conversation
    ON portal_support_messages(conversation_id, created_at);

ALTER TABLE portal_events DROP CONSTRAINT IF EXISTS portal_events_event_type_check;
ALTER TABLE portal_events
    ADD CONSTRAINT portal_events_event_type_check
    CHECK (event_type IN (
        'PORTAL_VIEW',
        'VOUCHER_SUBMITTED',
        'VOUCHER_REDEEM_SUCCESS',
        'VOUCHER_REDEEM_FAILED',
        'STATUS_VIEW',
        'MAC_REBIND_ATTEMPT',
        'MAC_REBIND_SUCCESS',
        'MAC_REBIND_FAILED',
        'MAC_REBIND_SKIPPED',
        'PAYMENT_CHECKOUT_CREATED',
        'PAYMENT_CHECKOUT_FAILED',
        'PAYMENT_STATUS_VIEW',
        'PAYMENT_WEBHOOK_RECEIVED',
        'PAYMENT_PAID',
        'PAYMENT_FAILED',
        'PAYMENT_FULFILLMENT_SUCCESS',
        'PAYMENT_FULFILLMENT_FAILED',
        'PROFILE_OTP_SENT',
        'PROFILE_SAVED',
        'WELCOME_GIFT_CREATED',
        'WELCOME_GIFT_REDEEMED',
        'MISSING_TIME_OTP_SENT',
        'MISSING_TIME_RESTORED',
        'SUPPORT_MESSAGE_CREATED'
    ));
