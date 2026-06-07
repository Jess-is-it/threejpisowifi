ALTER TABLE captive_portal_settings
    ADD COLUMN IF NOT EXISTS store_owner_purchase_request_sms_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS store_owner_purchase_request_sms_message TEXT NOT NULL DEFAULT 'New 3J store request at <STORE>: <CUSTOMER> wants <ITEMS> for <AMOUNT>. Open <STORE_PORTAL_URL> to approve.';

