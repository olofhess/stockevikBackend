// Stockevik 1.2.3: ingen offline-cache för privata uppgifter.
// Service worker används endast för PWA-installation och kan utvecklas senare.
self.addEventListener('install', event => {
  self.skipWaiting();
});
self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});
