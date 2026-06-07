self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (_error) {
    payload = { body: event.data ? event.data.text() : '' };
  }
  const targetUrl = payload.url || payload.data?.url || '/portal';
  const options = {
    body: payload.body || payload.message || '',
    tag: payload.tag || `3j-notification-${Date.now()}`,
    renotify: true,
    data: {
      ...(payload.data || {}),
      url: targetUrl,
    },
  };
  if (payload.icon) options.icon = payload.icon;
  if (payload.badge) options.badge = payload.badge;
  event.waitUntil(self.registration.showNotification(payload.title || '3J WiFi', options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = event.notification?.data?.url || '/portal';
  event.waitUntil((async () => {
    const windows = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of windows) {
      try {
        const clientUrl = new URL(client.url);
        if (clientUrl.origin === self.location.origin && 'focus' in client) {
          if ('navigate' in client) await client.navigate(targetUrl);
          return client.focus();
        }
      } catch (_error) {
        // Ignore malformed client URLs and keep looking for a usable window.
      }
    }
    if (clients.openWindow) return clients.openWindow(targetUrl);
    return undefined;
  })());
});
