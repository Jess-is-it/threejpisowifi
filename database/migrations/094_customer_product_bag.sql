ALTER TABLE captive_portal_settings
  ADD COLUMN IF NOT EXISTS outside_network_warning_enabled BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS outside_network_warning_message TEXT NOT NULL DEFAULT 'You are not currently connected to a 3J WiFi AP. Your time is visible here, but internet access only works when connected to a 3J WiFi network.',
  ADD COLUMN IF NOT EXISTS outside_network_purchase_title TEXT NOT NULL DEFAULT 'You are outside 3J WiFi',
  ADD COLUMN IF NOT EXISTS outside_network_purchase_message TEXT NOT NULL DEFAULT 'You can still buy this package, but it will be saved to your bag and will only activate when you connect to a 3J WiFi AP.',
  ADD COLUMN IF NOT EXISTS outside_network_purchase_success_message TEXT NOT NULL DEFAULT 'Package saved to your bag. Connect to a 3J WiFi AP to use it.',
  ADD COLUMN IF NOT EXISTS bag_auto_activate_default BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS bag_activation_overlap_seconds INTEGER NOT NULL DEFAULT 10;

CREATE TABLE IF NOT EXISTS customer_bag_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  auto_activate BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS customer_bag_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
  payment_order_id UUID REFERENCES payment_orders(id) ON DELETE SET NULL,
  voucher_id UUID REFERENCES vouchers(id) ON DELETE SET NULL,
  product_item_id UUID REFERENCES product_items(id) ON DELETE SET NULL,
  product_category_id UUID REFERENCES product_categories(id) ON DELETE SET NULL,
  product_name TEXT NOT NULL,
  product_category_name TEXT,
  source TEXT NOT NULL DEFAULT 'PAYMENT' CHECK (source IN ('PAYMENT', 'WELCOME_GIFT', 'MANUAL', 'VOUCHER')),
  status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'ACTIVE', 'CONSUMED', 'EXPIRED', 'CANCELLED')),
  priority INTEGER NOT NULL DEFAULT 1000,
  duration_seconds INTEGER NOT NULL DEFAULT 0,
  remaining_seconds INTEGER NOT NULL DEFAULT 0,
  activated_at TIMESTAMPTZ,
  active_until TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  auto_activate_snapshot BOOLEAN,
  overlap_seconds_snapshot INTEGER,
  device_scope TEXT NOT NULL DEFAULT 'SINGLE_DEVICE',
  allowed_devices INTEGER NOT NULL DEFAULT 1,
  access_scope TEXT NOT NULL DEFAULT 'ALL_LOCATIONS',
  allowed_barangay TEXT,
  purchase_quantity INTEGER NOT NULL DEFAULT 1,
  amount_centavos INTEGER,
  currency TEXT NOT NULL DEFAULT 'PHP',
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_bag_items_payment_order
  ON customer_bag_items(payment_order_id)
  WHERE payment_order_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_customer_bag_items_user_status_priority
  ON customer_bag_items(user_id, status, priority, created_at);

CREATE TABLE IF NOT EXISTS customer_bag_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  bag_item_id UUID REFERENCES customer_bag_items(id) ON DELETE SET NULL,
  portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  message TEXT,
  auto_activate_enabled BOOLEAN,
  overlap_seconds INTEGER,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_customer_bag_events_user_created
  ON customer_bag_events(user_id, created_at DESC);
