DO $$
DECLARE
    fk_name TEXT;
BEGIN
    SELECT conname
    INTO fk_name
    FROM pg_constraint
    WHERE conrelid = 'physical_store_items'::regclass
      AND contype = 'f'
      AND pg_get_constraintdef(oid) ILIKE '%REFERENCES physical_stores%'
    LIMIT 1;

    IF fk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE physical_store_items DROP CONSTRAINT %I', fk_name);
    END IF;
END $$;

ALTER TABLE physical_store_items
    ALTER COLUMN store_id DROP NOT NULL;

ALTER TABLE physical_store_items
    ADD CONSTRAINT physical_store_items_store_id_fkey
    FOREIGN KEY (store_id) REFERENCES physical_stores(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS physical_store_item_assignments (
    store_id UUID NOT NULL REFERENCES physical_stores(id) ON DELETE CASCADE,
    item_id UUID NOT NULL REFERENCES physical_store_items(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (store_id, item_id)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'physical_store_item_assignments_status_check'
    ) THEN
        ALTER TABLE physical_store_item_assignments
            ADD CONSTRAINT physical_store_item_assignments_status_check CHECK (status IN ('ACTIVE', 'DISABLED'));
    END IF;
END $$;

INSERT INTO physical_store_item_assignments(store_id, item_id, status, sort_order)
SELECT store_id, id, 'ACTIVE', sort_order
FROM physical_store_items
WHERE store_id IS NOT NULL
ON CONFLICT (store_id, item_id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_physical_store_item_assignments_item
    ON physical_store_item_assignments(item_id, status);

CREATE INDEX IF NOT EXISTS idx_physical_store_item_assignments_store
    ON physical_store_item_assignments(store_id, status, sort_order);
