CREATE TABLE IF NOT EXISTS physical_store_owners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_id UUID NOT NULL UNIQUE REFERENCES physical_stores(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    contact_number TEXT,
    normalized_contact TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    last_login_at TIMESTAMPTZ,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    ALTER TABLE customer_bag_items DROP CONSTRAINT IF EXISTS customer_bag_items_source_check;
    ALTER TABLE customer_bag_items
        ADD CONSTRAINT customer_bag_items_source_check CHECK (source IN ('PAYMENT', 'WELCOME_GIFT', 'MANUAL', 'VOUCHER', 'STORE_PURCHASE'));
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_owners_status_check'
    ) THEN
        ALTER TABLE physical_store_owners
            ADD CONSTRAINT physical_store_owners_status_check CHECK (status IN ('ACTIVE', 'DISABLED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_physical_store_owners_store_id
    ON physical_store_owners(store_id);

CREATE INDEX IF NOT EXISTS idx_physical_store_owners_normalized_contact
    ON physical_store_owners(normalized_contact)
    WHERE normalized_contact IS NOT NULL;

CREATE TABLE IF NOT EXISTS store_owner_trusted_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES physical_store_owners(id) ON DELETE CASCADE,
    device_token_hash TEXT NOT NULL,
    device_label TEXT,
    user_agent TEXT,
    last_ip INET,
    last_seen_at TIMESTAMPTZ,
    trusted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, device_token_hash)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_owner_trusted_devices_status_check'
    ) THEN
        ALTER TABLE store_owner_trusted_devices
            ADD CONSTRAINT store_owner_trusted_devices_status_check CHECK (status IN ('ACTIVE', 'REVOKED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_store_owner_trusted_devices_owner_status
    ON store_owner_trusted_devices(owner_id, status);

CREATE TABLE IF NOT EXISTS store_owner_login_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES physical_store_owners(id) ON DELETE CASCADE,
    device_token_hash TEXT,
    code_hash TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT 'LOGIN',
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_owner_login_challenges_purpose_check'
    ) THEN
        ALTER TABLE store_owner_login_challenges
            ADD CONSTRAINT store_owner_login_challenges_purpose_check CHECK (purpose IN ('LOGIN', 'PASSWORD_CHANGE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_owner_login_challenges_status_check'
    ) THEN
        ALTER TABLE store_owner_login_challenges
            ADD CONSTRAINT store_owner_login_challenges_status_check CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'FAILED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_store_owner_login_challenges_owner_status
    ON store_owner_login_challenges(owner_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS store_owner_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES physical_store_owners(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    device_token_hash TEXT,
    user_agent TEXT,
    ip_address INET,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_store_owner_sessions_owner_expires
    ON store_owner_sessions(owner_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS store_purchase_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_id TEXT NOT NULL UNIQUE,
    store_id UUID NOT NULL REFERENCES physical_stores(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    customer_profile_id UUID REFERENCES portal_customer_profiles(id) ON DELETE SET NULL,
    request_method TEXT NOT NULL,
    approval_code_hash TEXT,
    display_code TEXT,
    qr_payload TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    auto_activate_if_no_time BOOLEAN NOT NULL DEFAULT false,
    amount_centavos INTEGER NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'PHP',
    total_duration_seconds INTEGER NOT NULL DEFAULT 0,
    device_scope TEXT NOT NULL DEFAULT 'SINGLE_DEVICE',
    allowed_devices INTEGER NOT NULL DEFAULT 1,
    purchase_quantity INTEGER NOT NULL DEFAULT 1,
    customer_name TEXT,
    customer_contact_number TEXT,
    customer_device_label TEXT,
    rejection_reason TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_by_owner_id UUID REFERENCES physical_store_owners(id) ON DELETE SET NULL,
    approved_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    fulfilled_bag_item_id UUID REFERENCES customer_bag_items(id) ON DELETE SET NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_purchase_requests_method_check'
    ) THEN
        ALTER TABLE store_purchase_requests
            ADD CONSTRAINT store_purchase_requests_method_check CHECK (request_method IN ('SUBMITTED', 'QR', 'CODE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_purchase_requests_status_check'
    ) THEN
        ALTER TABLE store_purchase_requests
            ADD CONSTRAINT store_purchase_requests_status_check CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'store_purchase_requests_device_scope_check'
    ) THEN
        ALTER TABLE store_purchase_requests
            ADD CONSTRAINT store_purchase_requests_device_scope_check CHECK (device_scope IN ('SINGLE_DEVICE', 'MULTI_DEVICE'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_store_purchase_requests_store_status
    ON store_purchase_requests(store_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_store_purchase_requests_user_status
    ON store_purchase_requests(user_id, status, created_at DESC)
    WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_store_purchase_requests_session_status
    ON store_purchase_requests(portal_session_id, status, created_at DESC)
    WHERE portal_session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_store_purchase_requests_code_hash
    ON store_purchase_requests(approval_code_hash)
    WHERE approval_code_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS store_purchase_request_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES store_purchase_requests(id) ON DELETE CASCADE,
    store_item_id UUID REFERENCES physical_store_items(id) ON DELETE SET NULL,
    item_name TEXT NOT NULL,
    item_description TEXT,
    price_centavos INTEGER NOT NULL DEFAULT 0,
    quantity INTEGER NOT NULL DEFAULT 1,
    duration_seconds INTEGER NOT NULL DEFAULT 0,
    device_scope TEXT NOT NULL DEFAULT 'SINGLE_DEVICE',
    allowed_devices INTEGER NOT NULL DEFAULT 1,
    access_scope TEXT NOT NULL DEFAULT 'ALL_LOCATIONS',
    allowed_barangay TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_store_purchase_request_items_request
    ON store_purchase_request_items(request_id);
