CREATE TABLE IF NOT EXISTS payment_orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_order_id TEXT UNIQUE NOT NULL,
    provider TEXT NOT NULL DEFAULT 'PAYMONGO',
    provider_mode TEXT NOT NULL DEFAULT 'TEST' CHECK (provider_mode IN ('TEST', 'LIVE')),
    product_item_id UUID REFERENCES product_items(id) ON DELETE SET NULL,
    portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'CHECKOUT_CREATED', 'PAID', 'FAILED', 'CANCELLED', 'EXPIRED')),
    fulfillment_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (fulfillment_status IN ('PENDING', 'FULFILLED', 'FAILED', 'NOT_REQUIRED')),
    payment_method TEXT NOT NULL DEFAULT 'gcash',
    amount_centavos INTEGER NOT NULL CHECK (amount_centavos > 0),
    currency TEXT NOT NULL DEFAULT 'PHP',
    product_name TEXT NOT NULL,
    product_description TEXT,
    duration_seconds INTEGER NOT NULL CHECK (duration_seconds > 0),
    checkout_session_id TEXT,
    checkout_url TEXT,
    provider_payment_id TEXT,
    provider_event_id TEXT,
    provider_response_json JSONB,
    provider_webhook_json JSONB,
    client_mac TEXT,
    client_ip INET,
    user_agent TEXT,
    last_error TEXT,
    paid_at TIMESTAMPTZ,
    fulfilled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_payment_orders_public_order_id ON payment_orders(public_order_id);
CREATE INDEX IF NOT EXISTS idx_payment_orders_checkout_session_id ON payment_orders(checkout_session_id);
CREATE INDEX IF NOT EXISTS idx_payment_orders_portal_session_id ON payment_orders(portal_session_id);
CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status, fulfillment_status);
CREATE INDEX IF NOT EXISTS idx_payment_orders_created_at ON payment_orders(created_at DESC);

CREATE TABLE IF NOT EXISTS payment_webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL DEFAULT 'PAYMONGO',
    provider_mode TEXT,
    provider_event_id TEXT UNIQUE NOT NULL,
    event_type TEXT,
    payment_order_id UUID REFERENCES payment_orders(id) ON DELETE SET NULL,
    processing_status TEXT NOT NULL DEFAULT 'RECEIVED' CHECK (processing_status IN ('RECEIVED', 'PROCESSED', 'IGNORED', 'FAILED')),
    payload_json JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_payment_webhook_events_order ON payment_webhook_events(payment_order_id);
CREATE INDEX IF NOT EXISTS idx_payment_webhook_events_created_at ON payment_webhook_events(created_at DESC);

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
        'PAYMENT_FULFILLMENT_FAILED'
    ));
