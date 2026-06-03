CREATE TABLE IF NOT EXISTS physical_store_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_id UUID NOT NULL REFERENCES physical_stores(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    price NUMERIC(12,2) NOT NULL DEFAULT 0,
    duration_value INTEGER NOT NULL DEFAULT 1,
    duration_unit TEXT NOT NULL DEFAULT 'hours',
    device_scope TEXT NOT NULL DEFAULT 'SINGLE_DEVICE',
    allowed_devices INTEGER NOT NULL DEFAULT 1,
    access_scope TEXT NOT NULL DEFAULT 'ALL_LOCATIONS',
    allowed_barangay TEXT,
    more_info_enabled BOOLEAN NOT NULL DEFAULT false,
    more_info_text TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_by_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_items_duration_unit_check'
    ) THEN
        ALTER TABLE physical_store_items
            ADD CONSTRAINT physical_store_items_duration_unit_check CHECK (duration_unit IN ('minutes', 'hours', 'days'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_items_device_scope_check'
    ) THEN
        ALTER TABLE physical_store_items
            ADD CONSTRAINT physical_store_items_device_scope_check CHECK (device_scope IN ('SINGLE_DEVICE', 'MULTI_DEVICE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_items_access_scope_check'
    ) THEN
        ALTER TABLE physical_store_items
            ADD CONSTRAINT physical_store_items_access_scope_check CHECK (access_scope IN ('ALL_LOCATIONS', 'BARANGAY_ONLY'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_items_status_check'
    ) THEN
        ALTER TABLE physical_store_items
            ADD CONSTRAINT physical_store_items_status_check CHECK (status IN ('ACTIVE', 'DISABLED'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_items_duration_positive_check'
    ) THEN
        ALTER TABLE physical_store_items
            ADD CONSTRAINT physical_store_items_duration_positive_check CHECK (duration_value > 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_items_allowed_devices_positive_check'
    ) THEN
        ALTER TABLE physical_store_items
            ADD CONSTRAINT physical_store_items_allowed_devices_positive_check CHECK (allowed_devices > 0);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_physical_store_items_store_status
    ON physical_store_items(store_id, status, sort_order, name);

CREATE INDEX IF NOT EXISTS idx_physical_store_items_access_scope
    ON physical_store_items(access_scope, allowed_barangay);
