-- Remove the retired Shared Device Pass / Multi-Pass feature.
-- Existing customer time remains owned by the purchasing profile, but sharing
-- invitations and shared-device seat data are removed.

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'product_items' AND column_name = 'device_scope')
     AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'product_items' AND column_name = 'allowed_devices') THEN
    UPDATE product_items
    SET device_scope = 'SINGLE_DEVICE',
        allowed_devices = 1,
        updated_at = now()
    WHERE COALESCE(device_scope, 'SINGLE_DEVICE') <> 'SINGLE_DEVICE'
       OR COALESCE(allowed_devices, 1) <> 1;
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'payment_orders' AND column_name = 'device_scope')
     AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'payment_orders' AND column_name = 'allowed_devices') THEN
    UPDATE payment_orders
    SET device_scope = 'SINGLE_DEVICE',
        allowed_devices = 1,
        updated_at = now()
    WHERE COALESCE(device_scope, 'SINGLE_DEVICE') <> 'SINGLE_DEVICE'
       OR COALESCE(allowed_devices, 1) <> 1;
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'customer_bag_items' AND column_name = 'device_scope')
     AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'customer_bag_items' AND column_name = 'allowed_devices') THEN
    UPDATE customer_bag_items
    SET device_scope = 'SINGLE_DEVICE',
        allowed_devices = 1,
        updated_at = now()
    WHERE COALESCE(device_scope, 'SINGLE_DEVICE') <> 'SINGLE_DEVICE'
       OR COALESCE(allowed_devices, 1) <> 1;
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'physical_store_items' AND column_name = 'device_scope')
     AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'physical_store_items' AND column_name = 'allowed_devices') THEN
    UPDATE physical_store_items
    SET device_scope = 'SINGLE_DEVICE',
        allowed_devices = 1,
        updated_at = now()
    WHERE COALESCE(device_scope, 'SINGLE_DEVICE') <> 'SINGLE_DEVICE'
       OR COALESCE(allowed_devices, 1) <> 1;
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'store_purchase_requests' AND column_name = 'device_scope')
     AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'store_purchase_requests' AND column_name = 'allowed_devices') THEN
    UPDATE store_purchase_requests
    SET device_scope = 'SINGLE_DEVICE',
        allowed_devices = 1,
        updated_at = now()
    WHERE COALESCE(device_scope, 'SINGLE_DEVICE') <> 'SINGLE_DEVICE'
       OR COALESCE(allowed_devices, 1) <> 1;
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'store_purchase_request_items' AND column_name = 'device_scope')
     AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'store_purchase_request_items' AND column_name = 'allowed_devices') THEN
    UPDATE store_purchase_request_items
    SET device_scope = 'SINGLE_DEVICE',
        allowed_devices = 1
    WHERE COALESCE(device_scope, 'SINGLE_DEVICE') <> 'SINGLE_DEVICE'
       OR COALESCE(allowed_devices, 1) <> 1;
  END IF;
END $$;

DROP TABLE IF EXISTS customer_bag_item_shares CASCADE;

ALTER TABLE product_items
  DROP CONSTRAINT IF EXISTS product_items_device_scope_check,
  DROP CONSTRAINT IF EXISTS product_items_allowed_devices_check,
  DROP COLUMN IF EXISTS device_scope,
  DROP COLUMN IF EXISTS allowed_devices;

ALTER TABLE payment_orders
  DROP CONSTRAINT IF EXISTS payment_orders_device_scope_check,
  DROP CONSTRAINT IF EXISTS payment_orders_allowed_devices_check,
  DROP COLUMN IF EXISTS device_scope,
  DROP COLUMN IF EXISTS allowed_devices;

ALTER TABLE customer_bag_items
  DROP COLUMN IF EXISTS device_scope,
  DROP COLUMN IF EXISTS allowed_devices;

ALTER TABLE physical_store_items
  DROP CONSTRAINT IF EXISTS physical_store_items_device_scope_check,
  DROP CONSTRAINT IF EXISTS physical_store_items_allowed_devices_positive_check,
  DROP COLUMN IF EXISTS device_scope,
  DROP COLUMN IF EXISTS allowed_devices;

ALTER TABLE store_purchase_requests
  DROP CONSTRAINT IF EXISTS store_purchase_requests_device_scope_check,
  DROP COLUMN IF EXISTS device_scope,
  DROP COLUMN IF EXISTS allowed_devices;

ALTER TABLE store_purchase_request_items
  DROP COLUMN IF EXISTS device_scope,
  DROP COLUMN IF EXISTS allowed_devices;
