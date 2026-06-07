CREATE TABLE IF NOT EXISTS customer_bag_item_shares (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  bag_item_id UUID NOT NULL REFERENCES customer_bag_items(id) ON DELETE CASCADE,
  shared_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  shared_portal_session_id UUID REFERENCES portal_sessions(id) ON DELETE SET NULL,
  shared_contact_number TEXT,
  normalized_contact TEXT,
  share_code TEXT NOT NULL,
  share_token TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'QR' CHECK (method IN ('QR', 'CODE', 'CONTACT')),
  status TEXT NOT NULL DEFAULT 'INVITE' CHECK (status IN ('INVITE', 'PENDING_APPROVAL', 'ACTIVE', 'REVOKED', 'REJECTED', 'EXPIRED')),
  claimed_at TIMESTAMPTZ,
  approved_at TIMESTAMPTZ,
  rejected_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_bag_item_shares_code
  ON customer_bag_item_shares(share_code);

CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_bag_item_shares_token
  ON customer_bag_item_shares(share_token);

CREATE INDEX IF NOT EXISTS idx_customer_bag_item_shares_owner
  ON customer_bag_item_shares(owner_user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_customer_bag_item_shares_shared_user
  ON customer_bag_item_shares(shared_user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_customer_bag_item_shares_bag_item
  ON customer_bag_item_shares(bag_item_id, status);
