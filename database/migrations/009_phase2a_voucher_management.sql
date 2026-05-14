CREATE TABLE IF NOT EXISTS voucher_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_name TEXT NOT NULL,
    description TEXT,
    voucher_type TEXT NOT NULL CHECK (voucher_type IN ('TIME_BASED', 'DATE_BASED', 'UNLIMITED')),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    time_value_seconds INTEGER,
    valid_until TIMESTAMPTZ,
    unlimited_expires_at TIMESTAMPTZ,
    price NUMERIC(12,2),
    code_prefix TEXT,
    code_length INTEGER NOT NULL DEFAULT 8 CHECK (code_length BETWEEN 4 AND 32),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'COMPLETED', 'VOIDED')),
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vouchers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID REFERENCES voucher_batches(id) ON DELETE SET NULL,
    code TEXT NOT NULL,
    normalized_code TEXT NOT NULL,
    voucher_type TEXT NOT NULL CHECK (voucher_type IN ('TIME_BASED', 'DATE_BASED', 'UNLIMITED')),
    time_value_seconds INTEGER,
    valid_until TIMESTAMPTZ,
    is_unlimited BOOLEAN NOT NULL DEFAULT false,
    unlimited_expires_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'UNUSED' CHECK (status IN ('UNUSED', 'USED', 'EXPIRED', 'DISABLED', 'VOIDED')),
    max_redemptions INTEGER NOT NULL DEFAULT 1 CHECK (max_redemptions > 0),
    redemption_count INTEGER NOT NULL DEFAULT 0 CHECK (redemption_count >= 0),
    redeemed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    redeemed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    note TEXT,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS voucher_redemptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username TEXT,
    device_identifier TEXT,
    source TEXT NOT NULL CHECK (source IN ('ADMIN_TEST', 'CLIENT_PORTAL', 'SYSTEM')),
    wallet_transaction_id UUID REFERENCES transactions(id) ON DELETE SET NULL,
    result TEXT NOT NULL CHECK (result IN ('SUCCESS', 'FAILED')),
    failure_reason TEXT,
    redeemed_time_seconds INTEGER,
    redeemed_valid_until TIMESTAMPTZ,
    redeemed_unlimited BOOLEAN NOT NULL DEFAULT false,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vouchers_normalized_code ON vouchers(normalized_code);
CREATE INDEX IF NOT EXISTS idx_vouchers_status ON vouchers(status);
CREATE INDEX IF NOT EXISTS idx_vouchers_batch_id ON vouchers(batch_id);
CREATE INDEX IF NOT EXISTS idx_vouchers_redeemed_by_user_id ON vouchers(redeemed_by_user_id);
CREATE INDEX IF NOT EXISTS idx_vouchers_created_at ON vouchers(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_voucher_batches_created_at ON voucher_batches(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_voucher_redemptions_created_at ON voucher_redemptions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_voucher_redemptions_voucher_id ON voucher_redemptions(voucher_id);
