DO $$
DECLARE
    cfg JSONB;
    selected_mode TEXT;
    credentials JSONB;
    legacy_credentials JSONB;
BEGIN
    SELECT value INTO cfg FROM app_settings WHERE key = 'payment_gateway';
    IF cfg IS NULL THEN
        RETURN;
    END IF;

    selected_mode := CASE WHEN upper(coalesce(cfg->>'mode', 'TEST')) = 'LIVE' THEN 'LIVE' ELSE 'TEST' END;
    credentials := coalesce(cfg->'credentials', '{"TEST": {}, "LIVE": {}}'::jsonb);
    legacy_credentials := jsonb_strip_nulls(jsonb_build_object(
        'public_key', cfg->>'public_key',
        'secret_key_encrypted', cfg->>'secret_key_encrypted',
        'webhook_secret_encrypted', cfg->>'webhook_secret_encrypted'
    ));

    IF legacy_credentials <> '{}'::jsonb THEN
        credentials := jsonb_set(
            credentials,
            ARRAY[selected_mode],
            coalesce(credentials->selected_mode, '{}'::jsonb) || legacy_credentials,
            true
        );
    END IF;

    UPDATE app_settings
    SET value = (cfg - 'public_key' - 'secret_key_encrypted' - 'webhook_secret_encrypted')
        || jsonb_build_object('credentials', credentials),
        updated_at = now()
    WHERE key = 'payment_gateway';
END $$;
