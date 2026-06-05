ALTER TABLE portal_support_conversations
    ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'CUSTOMER',
    ADD COLUMN IF NOT EXISTS store_owner_id UUID REFERENCES physical_store_owners(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS physical_store_id UUID REFERENCES physical_stores(id) ON DELETE SET NULL;

UPDATE portal_support_conversations
SET source_type = 'CUSTOMER'
WHERE source_type IS NULL OR source_type = '';

DO $$
BEGIN
    ALTER TABLE portal_support_conversations DROP CONSTRAINT IF EXISTS portal_support_conversations_source_type_check;
    ALTER TABLE portal_support_conversations
        ADD CONSTRAINT portal_support_conversations_source_type_check
        CHECK (source_type IN ('CUSTOMER', 'STORE_OWNER'));
END $$;

DO $$
BEGIN
    ALTER TABLE portal_support_messages DROP CONSTRAINT IF EXISTS portal_support_messages_sender_type_check;
    ALTER TABLE portal_support_messages
        ADD CONSTRAINT portal_support_messages_sender_type_check
        CHECK (sender_type IN ('CUSTOMER', 'STORE_OWNER', 'ADMIN', 'SYSTEM'));
END $$;

CREATE INDEX IF NOT EXISTS idx_portal_support_conversations_source_status
    ON portal_support_conversations(source_type, status, last_message_at DESC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_portal_support_conversations_store_owner_status
    ON portal_support_conversations(store_owner_id, status, last_message_at DESC NULLS LAST)
    WHERE store_owner_id IS NOT NULL;
