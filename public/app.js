'use strict';
// Version 0.6. The web page is served by the Stockevik backend on the SAME origin.
// Authentication and member identities are controlled by the server, never by localStorage.
const $ = id => document.getElementById(id);
let currentMember = null;
let posts = [];
let members = [];

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
  if (signedIn) $('registrationView').classList.add('hide');
}
function view(tab) {
  if (tab === 'admin' && currentMember?.role !== 'admin') tab='feed';
  for (const t of ['feed','members','admin']) {
    $(t+'View').classList.toggle('hide',t!==tab);
    $(t+'Tab').classList.toggle('active',t===tab);
  }
  if (tab === 'members') loadMembers();
  if (tab === 'feed') loadPosts();
  if (tab === 'admin') loadApplications();
}
$('feedTab').onclick = () => view('feed');
$('membersTab').onclick = () => view('members');
$('adminTab').onclick = () => view('admin');

function renderPosts() {
  const host = $('posts'); host.replaceChildren();
  if (!posts.length) { host.append(element('div','card empty','Inga inlägg ännu. Skriv det första!')); return; }
  for (const p of posts) {
    const card = element('article','card');
    const header = element('div','postheader');
    header.append(element('div','avatar',(p.author || '?').slice(0,1).toUpperCase()));
    const by = element('div');
    by.append(element('div','by',p.author || ''), element('div','date',formatDate(p.date)));
    header.append(by);
    card.append(header);
    const postText = element('div','posttext',p.text || '');
    card.append(postText);
    // The button is just a convenience. The server independently enforces ownership.
    if (currentMember && String(p.authorId) === String(currentMember.id)) {
      const editActions = element('div','actions');
      const editButton = element('button','btn subtle','Redigera');
      editButton.type = 'button';
      editActions.append(editButton);
      card.append(editActions);
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
      item.append(element('b','',`${c.author} · ${formatDate(c.date)}`), element('p','',c.text || ''));
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
$('postBtn').onclick = async () => {
  const text = $('postText').value.trim();
  if (!text) { $('postText').focus(); return; }
  const button = $('postBtn'); button.disabled = true;
  try {
    await api('/posts','POST',{text});
    $('postText').value = '';
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
