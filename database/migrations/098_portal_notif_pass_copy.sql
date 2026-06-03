UPDATE captive_portal_settings
SET portal_success_notification_message = 'WiFi pass active. Remaining time: <TIME>.'
WHERE portal_success_notification_message = 'Voucher accepted. Remaining time: <TIME>.';

UPDATE captive_portal_settings
SET portal_remaining_notification_message = 'Reminder: only <TIME> remaining on your active WiFi pass.'
WHERE portal_remaining_notification_message = 'Reminder: only <TIME> remaining on your WiFi voucher.';

UPDATE captive_portal_settings
SET portal_expired_notification_message = 'Your WiFi pass time is fully consumed. Buy another package or claim a voucher to continue.'
WHERE portal_expired_notification_message = 'Your WiFi voucher time is fully consumed. Enter a new voucher to continue.';

