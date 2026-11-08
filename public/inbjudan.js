"use strict";
(async () => {
  const status = document.getElementById('status');
  const details = document.getElementById('details');
  // Only the URL fragment carries the key; it is not included in HTTP requests.
  const token = location.hash.startsWith('#token=') ? location.hash.slice(7) : '';
  // Clear the secret from the browser address bar and history immediately.
  history.replaceState(null, '', location.pathname);
  if (!/^[a-f0-9]{64}$/.test(token)) {
    status.textContent = 'Inbjudningslänken är ogiltig eller saknar nyckel.';
    return;
  }
  try {
    const response = await fetch('/api/invitations/preview', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type':'application/json'},
      cache: 'no-store',
      body: JSON.stringify({token})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Inbjudan kunde inte öppnas.');
    document.getElementById('group').textContent = data.groupName;
    document.getElementById('email').textContent = data.email;
    details.hidden = false;
    status.textContent = '';
  } catch (err) { status.textContent = err.message; }
})();
