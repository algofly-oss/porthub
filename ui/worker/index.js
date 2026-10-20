/* eslint-env serviceworker */

// Older service workers cached GET API responses. Remove those entries when
// upgrading, while preserving the public app shell and static assets.
self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(names => Promise.all(names.map(async name => {
    const cache = await caches.open(name);
    const requests = await cache.keys();
    await Promise.all(requests.filter(request => {
      const url = new URL(request.url);
      return url.origin === self.location.origin &&
        (url.pathname.startsWith("/api/") || url.pathname.startsWith("/socket.io/"));
    }).map(request => cache.delete(request)));
  }))));
});
