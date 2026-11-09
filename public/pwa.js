// Lillachatten: ingen offline-cache för privata API-svar.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(err => console.warn('PWA kunde inte aktiveras:', err));
  });
}
