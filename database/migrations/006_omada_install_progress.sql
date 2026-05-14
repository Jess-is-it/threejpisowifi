ALTER TABLE omada_install_logs ADD COLUMN IF NOT EXISTS progress_percent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE omada_install_logs ADD COLUMN IF NOT EXISTS current_step TEXT;

UPDATE omada_install_logs
SET progress_percent = CASE WHEN status = 'SUCCESS' THEN 100 ELSE progress_percent END,
    current_step = COALESCE(current_step, CASE WHEN status = 'SUCCESS' THEN 'Complete' WHEN status = 'FAILED' THEN 'Failed' ELSE 'Queued' END);
