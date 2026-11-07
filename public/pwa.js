// Installerbar webbapp. Cacha aldrig privata API-svar eller medlemsbilder.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(err => {
      console.warn('PWA-registrering misslyckades:', err);
    });
  });
}
