DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'customer_bag_items_iptv_status_check'
    ) THEN
        ALTER TABLE customer_bag_items DROP CONSTRAINT customer_bag_items_iptv_status_check;
    END IF;

    ALTER TABLE customer_bag_items
        ADD CONSTRAINT customer_bag_items_iptv_status_check
        CHECK (iptv_status IN ('NOT_REQUIRED', 'PENDING', 'MANUAL_REVIEW', 'PROVISIONED', 'FAILED', 'DELETED'));
END $$;
