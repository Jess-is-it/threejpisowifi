ALTER TABLE store_owner_login_challenges
    DROP CONSTRAINT IF EXISTS store_owner_login_challenges_purpose_check;

ALTER TABLE store_owner_login_challenges
    ADD CONSTRAINT store_owner_login_challenges_purpose_check
    CHECK (purpose IN ('LOGIN', 'PASSWORD_CHANGE', 'PIN_CHANGE'));
