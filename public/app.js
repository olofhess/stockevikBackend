'use strict';
// Version 1.0. The web page is served by the Stockevik backend on the SAME origin.
// Authentication and member identities are controlled by the server, never by localStorage.
const $ = id => document.getElementById(id);
let currentMember = null;
let posts = [];
let members = [];
let pendingPostPhoto = null; // compressed base64, held only until publication

function avatar(name, id, version, small=false) {
  const holder = element('span', small ? 'avatar avatar-small' : 'avatar');
  holder.textContent = (name || '?').slice(0,1).toUpperCase();
  if (version && id != null) {
    const img = document.createElement('img');
    img.src = '/api/avatars/' + encodeURIComponent(id) + '?v=' + encodeURIComponent(version);
    img.alt = ''; img.loading = 'lazy';
    img.onerror = () => img.remove();
    holder.append(img);
  }
  return holder;
}


function element(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
}
function formatDate(value) {
  if (!value) return '';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString('sv-SE', {dateStyle:'medium',timeStyle:'short'});
}
async function api(path, method='GET', data) {
  let response;
  try {
    response = await fetch('/api' + path, {
      method,
      credentials:'same-origin',
      headers: data === undefined ? {} : {'Content-Type':'application/json'},
      body: data === undefined ? undefined : JSON.stringify(data)
    });
  } catch {
    throw new Error('Ingen kontakt med Stockeviks server. Försök igen.');
  }
  let result = {};
  try { result = await response.json(); } catch {}
  if (!response.ok) {
    // Do not silently hide the page on a 401. The caller displays the error.
    throw new Error(result.error || 'Servern svarade med fel ' + response.status + '.');
  }
  return result;
}
function showSession() {
  const signedIn = !!currentMember;
  $('loginView').classList.toggle('hide', signedIn);
  $('appWrap').classList.toggle('hide', !signedIn);
  $('account').classList.toggle('hide', !signedIn);
  $('accountName').textContent = signedIn ? 'Inloggad som ' + currentMember.name : '';
  $('adminTab').classList.toggle('hide', !signedIn || currentMember.role !== 'admin');
  if (signedIn) { $('avatarRemove').classList.toggle('hide', !currentMember.avatarVersion); renderProfile(); }
  if (!signedIn) $('avatarStatus').textContent = '';
  if (signedIn) $('registrationView').classList.add('hide');
}
function view(tab) {
  if (tab === 'admin' && currentMember?.role !== 'admin') tab='feed';
  for (const t of ['feed','members','profile','admin']) {
    $(t+'View').classList.toggle('hide',t!==tab);
    $(t+'Tab').classList.toggle('active',t===tab);
  }
  if (tab === 'members') loadMembers();
  if (tab === 'profile') renderProfile();
  if (tab === 'feed') loadPosts();
  if (tab === 'admin') loadApplications();
}
$('feedTab').onclick = () => view('feed');
$('membersTab').onclick = () => view('members');
$('adminTab').onclick = () => view('admin');
$('profileTab').onclick = () => view('profile');

function renderPosts() {
  const host = $('posts'); host.replaceChildren();
  if (!posts.length) { host.append(element('div','card empty','Inga inlägg ännu. Skriv det första!')); return; }
  for (const p of posts) {
    const card = element('article','card');
    const header = element('div','postheader');
    header.append(avatar(p.author, p.authorId, p.avatarVersion));
    const by = element('div');
    by.append(element('div','by',p.author || ''), element('div','date',formatDate(p.date)));
    header.append(by);
    card.append(header);
    const postText = element('div','posttext',p.text || '');
    card.append(postText);
    if (p.hasImage) {
      const link = element('a','post-photo-link');
      link.href = '/api/posts/' + encodeURIComponent(p.id) + '/image';
      link.target = '_blank'; link.rel = 'noopener noreferrer';
      link.title = 'Visa bilden större';
      link.setAttribute('aria-label','Visa inläggets bild större');
      const img = document.createElement('img');
      img.className = 'post-photo';
      img.src = link.href;
      img.alt = 'Bild till inlägg av ' + (p.author || 'medlem');
      img.loading = 'lazy';
      link.append(img); card.append(link);
    }
    // The button is just a convenience. The server independently enforces ownership.
    if (currentMember && String(p.authorId) === String(currentMember.id)) {
      const editActions = element('div','actions');
      const editButton = element('button','linkbtn','✏️');
      editButton.title = 'Redigera inlägg';
      editButton.setAttribute('aria-label','Redigera mitt inlägg');
      editButton.type = 'button';
      const deleteButton = element('button','linkbtn','🗑️');
      deleteButton.type = 'button';
      deleteButton.title = 'Ta bort inlägg';
      deleteButton.setAttribute('aria-label','Ta bort mitt inlägg');
      deleteButton.style.marginLeft = '16px';
      editActions.append(editButton, deleteButton);
      card.append(editActions);
      deleteButton.onclick = async () => {
        if (!confirm('Ta bort ditt inlägg och alla dess kommentarer? Detta går inte att ångra.')) return;
        deleteButton.disabled = true;
        editButton.disabled = true;
        try {
          await api('/posts/' + p.id, 'DELETE');
          await loadPosts();
        } catch (err) {
          alert(err.message);
          deleteButton.disabled = false;
          editButton.disabled = false;
        }
      };
      editButton.onclick = () => {
        if (card.querySelector('.posteditform')) return;
        const form = element('form','posteditform');
        const field = element('textarea');
        field.maxLength = 5000;
        field.required = true;
        field.value = p.text || '';
        field.setAttribute('aria-label','Redigera inlägg');
        const controls = element('div','actions');
        const cancel = element('button','btn subtle','Avbryt');
        cancel.type = 'button';
        const save = element('button','btn','Spara');
        save.type = 'submit';
        controls.append(cancel,save);
        form.append(field,controls);
        postText.classList.add('hide');
        editActions.classList.add('hide');
        postText.after(form);
        const close = () => {
          form.remove();
          postText.classList.remove('hide');
          editActions.classList.remove('hide');
        };
        cancel.onclick = close;
        form.onsubmit = async event => {
          event.preventDefault();
          const text = field.value.trim();
          if (!text) { field.focus(); return; }
          save.disabled = true;
          cancel.disabled = true;
          try {
            await api('/posts/' + p.id, 'PUT', {text});
            await loadPosts();
          } catch (err) {
            alert(err.message);
            save.disabled = false;
            cancel.disabled = false;
          }
        };
        field.focus();
      };
    }
    const comments = Array.isArray(p.comments) ? p.comments : [];
    const footer = element('div','postfooter');
    const toggle = element('button','linkbtn',`💬 Kommentarer (${comments.length})`);
    toggle.type = 'button'; footer.append(toggle); card.append(footer);
    const area = element('div','hide');
    for (const c of comments) {
      const item = element('div','comment');
      const who = element('div','comment-author');
      who.append(avatar(c.author, c.authorId, c.avatarVersion, true), element('b','',`${c.author} · ${formatDate(c.date)}`));
      item.append(who, element('p','',c.text || ''));
      area.append(item);
    }
    const form = element('form','commentform');
    const input = document.createElement('input');
    input.required = true; input.maxLength = 2000;
    input.placeholder = 'Skriv en kommentar …';
    input.setAttribute('aria-label','Skriv en kommentar');
    const send = element('button','btn','Svara'); send.type='submit';
    form.append(input,send);
    form.onsubmit = async event => {
      event.preventDefault();
      const text = input.value.trim(); if (!text) return;
      send.disabled = true;
      try {
        await api('/posts/' + p.id + '/comments','POST',{text});
        await loadPosts();
      } catch(e) { alert(e.message); } finally { send.disabled = false; }
    };
    area.append(form);
    toggle.onclick = () => area.classList.toggle('hide');
    card.append(area); host.append(card);
  }
}
async function loadPosts() {
  $('feedStatus').textContent = 'Hämtar inlägg …';
  try {
    const result = await api('/posts');
    posts = result.posts || [];
    renderPosts();
    $('feedStatus').textContent = '';
  } catch(e) { $('feedStatus').textContent = e.message; }
}
// A single photograph per post. Canvas resizes and strips metadata before upload.
function clearPostPhoto() {
  pendingPostPhoto = null;
  $('postPhotoFile').value = '';
  $('postPhotoPreview').replaceChildren();
  $('postPhotoPreview').classList.add('hide');
  $('postPhotoRemove').classList.add('hide');
  $('postPhotoStatus').textContent = '';
}
$('postPhotoPick').onclick = () => $('postPhotoFile').click();
$('postPhotoRemove').onclick = clearPostPhoto;
$('postPhotoFile').onchange = async () => {
  const file = $('postPhotoFile').files?.[0];
  if (!file) return;
  pendingPostPhoto = null;
  $('postPhotoPreview').replaceChildren();
  $('postPhotoPreview').classList.add('hide');
  $('postPhotoRemove').classList.add('hide');
  const status = $('postPhotoStatus');
  const pick = $('postPhotoPick');
  pick.disabled = true;
  status.textContent = 'Förbereder bilden …';
  let url;
  try {
    if (!file.type.startsWith('image/') || file.size > 15 * 1024 * 1024) {
      throw new Error('Välj ett fotografi på högst 15 MB.');
    }
    url = URL.createObjectURL(file);
    const img = new Image();
    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = () => reject(new Error('Bilden kunde inte öppnas.'));
      img.src = url;
    });
    const factor = Math.min(1, 1200 / Math.max(img.naturalWidth,img.naturalHeight));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(img.naturalWidth * factor));
    canvas.height = Math.max(1, Math.round(img.naturalHeight * factor));
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Bilden kunde inte bearbetas.');
    ctx.drawImage(img,0,0,canvas.width,canvas.height);
    let dataURL;
    for (const quality of [0.78,0.65,0.52,0.40]) {
      dataURL = canvas.toDataURL('image/jpeg',quality);
      if (dataURL.length < 395000) break;
    }
    if (!dataURL.startsWith('data:image/jpeg;base64,') || dataURL.length >= 395000) {
      throw new Error('Fotografiet blev för stort. Välj en annan bild.');
    }
    pendingPostPhoto = dataURL.split(',')[1];
    const preview = document.createElement('img');
    preview.src = dataURL; preview.alt = 'Förhandsvisning av bilden';
    $('postPhotoPreview').append(preview);
    $('postPhotoPreview').classList.remove('hide');
    $('postPhotoRemove').classList.remove('hide');
    status.textContent = 'Bilden är klar att publiceras.';
  } catch(err) { status.textContent = err.message; }
  finally { if (url) URL.revokeObjectURL(url); pick.disabled = false; $('postPhotoFile').value = ''; }
};
$('postBtn').onclick = async () => {
  const text = $('postText').value.trim();
  if (!text) { $('postText').focus(); return; }
  const button = $('postBtn'); button.disabled = true;
  try {
    await api('/posts','POST',{text, ...(pendingPostPhoto ? {jpegBase64:pendingPostPhoto} : {})});
    $('postText').value = '';
    clearPostPhoto();
    await loadPosts();
  } catch(e) { alert(e.message); } finally { button.disabled = false; }
};
async function loadMembers() {
  const host = $('membersList');
  try {
    const result = await api('/members'); members = result.members || [];
    host.replaceChildren();
    for (const m of members) {
      const row = element('tr');
      for (const value of [m.name,m.house,m.username,'Aktiv']) row.append(element('td','',value || '–'));
      host.append(row);
    }
  } catch(e) { host.replaceChildren(element('tr','',e.message)); }
}

$('registerToggle').onclick=()=>{
  $('loginView').classList.add('hide');
  $('registrationView').classList.remove('hide');
};
$('registrationBack').onclick=()=>{
  $('registrationView').classList.add('hide');
  $('loginView').classList.remove('hide');
};
$('registrationForm').onsubmit=async e=>{
  e.preventDefault();
  const form=$('registrationForm');
  const button=form.querySelector('button[type=submit]');
  const status=$('registrationStatus');
  status.textContent='Skickar ansökan …'; button.disabled=true;
  try {
    const result=await api('/register','POST',{
      name:$('regName').value, house:$('regHouse').value,
      email:$('regEmail').value, password:$('regPassword').value
    });
    status.textContent=result.message;
    form.reset();
  } catch(err) { status.textContent=err.message; }
  finally { button.disabled=false; }
};
async function loadApplications() {
  const host=$('applicationsList');
  host.replaceChildren();
  $('adminStatus').textContent='Hämtar ansökningar …';
  try {
    const result=await api('/admin/applications');
    const applications=result.applications||[];
    $('adminStatus').textContent=applications.length ? '' : 'Inga väntande ansökningar.';
    for(const a of applications) {
      const card=element('div','comment');
      card.append(element('b','',a.name+' · '+a.house));
      card.append(element('p','',a.email));
      const actions=element('div','actions');
      for(const [decision,label] of [['approve','Godkänn'],['reject','Avslå']]) {
        const button=element('button',decision==='approve'?'btn':'btn subtle',label);
        button.type='button';
        button.onclick=async()=>{
          if(!confirm(`${label} ansökan från ${a.name}?`))return;
          button.disabled=true;
          try {
            await api('/admin/applications/'+a.id+'/decision','POST',{decision});
            await loadApplications();
          } catch(err) { alert(err.message); button.disabled=false; }
        };
        actions.append(button);
      }
      card.append(actions); host.append(card);
    }
  } catch(err) { $('adminStatus').textContent=err.message; }
}

$('loginForm').onsubmit = async event => {
  event.preventDefault();
  const button = $('loginForm').querySelector('button[type="submit"]');
  const error = $('loginError'); error.textContent = '';
  button.disabled = true;
  try {
    const result = await api('/login','POST',{
      email: $('loginEmail').value.trim(),
      password: $('loginPassword').value
    });
    // Verify that Safari actually retained and returns the session cookie.
    // A successful password check is not enough if the browser loses the cookie.
    let confirmed;
    try {
      confirmed = await api('/me');
    } catch (verifyError) {
      throw new Error('Lösenordet godkändes, men sessionen sparades inte i webbläsaren. Kontrollera att sidan öppnas på stockevikbackend.onrender.com och att cookies tillåts. (' + verifyError.message + ')');
    }
    currentMember = confirmed.member;
    $('loginPassword').value = '';
    showSession();
    view('feed');
  } catch(e) { error.textContent = e.message; }
  finally { button.disabled = false; }
};
$('logoutBtn').onclick = async () => {
  try { await api('/logout','POST'); }
  catch(e) { alert(e.message); return; }
  currentMember = null; posts = []; members = [];
  $('postText').value = '';
  showSession();
};
(async function init() {
  // Avoid an initial /me request overwriting a successful manual login.
  const initialRequest = api('/me');
  try {
    const result = await initialRequest;
    if (currentMember) return;
    currentMember = result.member;
    showSession();
    await loadPosts();
  } catch {
    if (!currentMember) showSession();
  }
})();

// A single profile photo per account. Canvas strips photo metadata and shrinks image.
$('avatarPick').onclick = () => $('avatarFile').click();
$('avatarFile').onchange = async () => {
  const file = $('avatarFile').files?.[0];
  if (!file) return;
  if (!file.type.startsWith('image/') || file.size > 12 * 1024 * 1024) {
    alert('Välj en bild på högst 12 MB.'); $('avatarFile').value = ''; return;
  }
  const button = $('avatarPick'); button.disabled = true;
  $('avatarStatus').textContent = 'Förbereder bilden …';
  let url;
  try {
    url = URL.createObjectURL(file);
    const image = new Image();
    await new Promise((resolve,reject) => {
      image.onload = resolve;
      image.onerror = () => reject(new Error('Bilden kunde inte öppnas.'));
      image.src = url;
    });
    const canvas = document.createElement('canvas');
    const side = 256;
    canvas.width = side; canvas.height = side;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Kan inte bearbeta bilden.');
    const width = image.naturalWidth, height = image.naturalHeight;
    const square = Math.min(width,height);
    ctx.drawImage(image,(width-square)/2,(height-square)/2,square,square,0,0,side,side);
    const jpegBase64 = canvas.toDataURL('image/jpeg',0.75).split(',')[1];
    const result = await api('/me/avatar', 'PUT', {jpegBase64});
    currentMember.avatarVersion = result.avatarVersion;
    $('avatarStatus').textContent = 'Profilbilden är sparad.';
    $('avatarRemove').classList.remove('hide');
    renderProfilePhoto();
    await loadPosts();
  } catch(err) { $('avatarStatus').textContent = err.message; }
  finally { if (url) URL.revokeObjectURL(url); button.disabled = false; $('avatarFile').value = ''; }
};
$('avatarRemove').onclick = async () => {
  if (!confirm('Ta bort din profilbild?')) return;
  try {
    await api('/me/avatar','DELETE');
    currentMember.avatarVersion = null;
    $('avatarRemove').classList.add('hide');
    renderProfilePhoto();
    $('avatarStatus').textContent = 'Profilbilden är borttagen.';
    await loadPosts();
  } catch(err) { $('avatarStatus').textContent = err.message; }
};


// The current member can change personal fields and password only through authenticated API calls.
function renderProfilePhoto() {
  const host = $('profilePhoto');
  host.replaceChildren();
  if (currentMember) host.append(avatar(currentMember.name, currentMember.id, currentMember.avatarVersion));
}
function renderProfile() {
  if (!currentMember) return;
  renderProfilePhoto();
  $('profileName').value = currentMember.name || '';
  $('profileHouse').value = currentMember.house || '';
  $('profileEmail').value = currentMember.email || '';
}
$('profileForm').onsubmit = async event => {
  event.preventDefault();
  const button = $('profileForm').querySelector('button[type="submit"]');
  const status = $('profileStatus');
  button.disabled = true; status.textContent = 'Sparar …';
  try {
    const result = await api('/me/profile','PUT',{
      name:$('profileName').value, house:$('profileHouse').value
    });
    currentMember = result.member;
    $('accountName').textContent = 'Inloggad som ' + currentMember.name;
    status.textContent = 'Profilen är sparad.';
    renderProfilePhoto();
    await loadPosts();
  } catch(err) { status.textContent = err.message; }
  finally { button.disabled = false; }
};
$('passwordForm').onsubmit = async event => {
  event.preventDefault();
  const status = $('passwordStatus');
  const button = $('passwordForm').querySelector('button[type="submit"]');
  const oldPassword = $('oldPassword').value;
  const newPassword = $('newPassword').value;
  if (newPassword !== $('confirmPassword').value) {
    status.textContent = 'De nya lösenorden är inte lika.'; return;
  }
  button.disabled = true; status.textContent = 'Ändrar lösenord …';
  try {
    await api('/me/password','PUT',{oldPassword,newPassword});
    $('passwordForm').reset();
    status.textContent = 'Lösenordet är ändrat.';
  } catch(err) { status.textContent = err.message; }
  finally { button.disabled = false; }
};
