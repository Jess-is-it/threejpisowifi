-- Allow store owners to disable the PIN reuse window.
-- 0 means every approval requires the PIN; 1-30 means remember it for that many minutes.

ALTER TABLE physical_store_owners
    DROP CONSTRAINT IF EXISTS physical_store_owners_pin_interval_check;

ALTER TABLE physical_store_owners
    ADD CONSTRAINT physical_store_owners_pin_interval_check
        CHECK (pin_required_interval_minutes BETWEEN 0 AND 30);
