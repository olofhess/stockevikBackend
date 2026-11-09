'use strict';
// Lillachatten version 17. The web page and API share one origin.
// Authentication and member identities are controlled by the server, never by localStorage.
const $ = id => document.getElementById(id);
const newMemberEmail = new URLSearchParams(location.search).get('registered');
if (newMemberEmail) {
  history.replaceState(null, '', location.pathname);
  document.addEventListener('DOMContentLoaded', () => {
    $('loginEmail').value = newMemberEmail;
    $('loginError').textContent = 'Registreringen är klar. Välkommen! Ange ditt lösenord och logga in.';
    $('loginPassword').focus();
  });
}

let currentMember = null;
let posts = [];
let members = [];
let associationProfile = null;
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
    throw new Error('Ingen kontakt med Lillachattens server. Försök igen.');
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
  $('settingsTab').classList.toggle('hide', !signedIn || currentMember.role !== 'admin');
  if (signedIn) { $('avatarRemove').classList.toggle('hide', !currentMember.avatarVersion); renderProfile(); }
  if (!signedIn) $('avatarStatus').textContent = '';

}
function view(tab) {
  if (['admin','settings'].includes(tab) && currentMember?.role !== 'admin') tab='feed';
  if (currentMember?.role === 'admin' && associationProfile && !associationProfile.configured) tab='setup';
  for (const t of ['feed','members','profile','admin','settings','setup']) {
    $(t+'View').classList.toggle('hide',t!==tab);
    if ($(t+'Tab')) $(t+'Tab').classList.toggle('active',t===tab);
  }
  if (tab === 'members') { loadMembers(); loadAdminMembers(); }
  if (tab === 'profile') renderProfile();
  if (tab === 'feed') loadPosts();

  if (tab === 'settings') fillAssociationForm();
}
$('feedTab').onclick = () => view('feed');
$('membersTab').onclick = () => view('members');
$('adminTab').onclick = () => view('admin');
$('profileTab').onclick = () => view('profile');
$('settingsTab').onclick = () => view('settings');

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
    // Reactions apply to the entire post, including an attached image.
    // A member can choose one; pressing the selected choice again removes it.
    const reactionBar = element('div', 'reaction-bar');
    const choices = [
      ['up', '👍', 'Tumme upp'],
      ['down', '👎', 'Tumme ner'],
      ['heart', '❤️', 'Hjärta']
    ];
    for (const [value, emoji, label] of choices) {
      const selected = p.myReaction === value;
      const button = element('button', selected ? 'reaction-button selected' : 'reaction-button');
      button.type = 'button';
      button.title = selected ? 'Ta bort ' + label.toLowerCase() : label;
      button.setAttribute('aria-label', button.title);
      button.setAttribute('aria-pressed', String(selected));
      button.append(element('span', 'reaction-emoji', emoji));
      button.append(element('span', 'reaction-count', String(p.reactions?.[value] || 0)));
      button.onclick = async () => {
        reactionBar.querySelectorAll('button').forEach(b => b.disabled = true);
        try {
          await api('/posts/' + p.id + '/reaction', 'PUT',
            {reaction: selected ? null : value});
          await loadPosts();
        } catch (err) {
          alert(err.message);
          reactionBar.querySelectorAll('button').forEach(b => b.disabled = false);
        }
      };
      reactionBar.append(button);
    }
    card.append(reactionBar);
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

// The member directory remains public only to signed-in members.
// Editing and contact details are loaded separately for administrators.
async function loadAdminMembers() {
  const admin = currentMember?.role === 'admin';
  $('memberAdmin').classList.toggle('hide', !admin);
  if (!admin) return;
  const host = $('adminMembersList');
  host.replaceChildren();
  $('adminMembersStatus').textContent = 'Hämtar medlemsuppgifter …';
  try {
    const result = await api('/admin/members');
    const all = result.members || [];
    $('adminMembersStatus').textContent = all.length ? '' : 'Inga medlemmar att hantera.';
    for (const m of all) {
      const card = element('div','member-admin-card');
      const header = element('div','member-admin-header');
      header.append(element('b','',m.name+' · '+(m.status === 'active' ? 'Aktiv' : 'Inaktiv')));
      const edit = element('button','btn subtle','✏️ Redigera'); edit.type='button';
      header.append(edit);
      // Password reset is a separate action; regular members never see it.
      // Admin accounts change their password using 'Min profil'.
      let resetForm = null;
      if (m.role !== 'admin') {
        const resetButton = element('button','btn subtle','Återställ lösenord');
        resetButton.type = 'button';
        header.append(resetButton);
        resetForm = element('form','member-admin-form hide');
        const resetTitle=element('p','small','Ange ett nytt tillfälligt lösenord (minst 8 tecken). Medlemmen behöver få det direkt av dig.');
        const resetField=element('div','field');
        const resetLabel=element('label','','Nytt lösenord');
        const resetInput=document.createElement('input');
        resetInput.type='password'; resetInput.minLength=8; resetInput.maxLength=200;
        resetInput.required=true; resetInput.autocomplete='new-password';
        resetInput.id='reset-password-'+m.id; resetLabel.htmlFor=resetInput.id;
        resetField.append(resetLabel,resetInput);
        const confirmField=element('div','field');
        const confirmLabel=element('label','','Upprepa lösenordet');
        const confirmInput=document.createElement('input');
        confirmInput.type='password'; confirmInput.minLength=8; confirmInput.maxLength=200;
        confirmInput.required=true; confirmInput.autocomplete='new-password';
        confirmInput.id='reset-confirm-'+m.id; confirmLabel.htmlFor=confirmInput.id;
        confirmField.append(confirmLabel,confirmInput);
        const resetActions=element('div','actions');
        const resetCancel=element('button','btn subtle','Avbryt'); resetCancel.type='button';
        const resetSave=element('button','btn','Spara nytt lösenord'); resetSave.type='submit';
        const resetFeedback=element('p','small'); resetFeedback.setAttribute('role','status');
        resetActions.append(resetCancel,resetSave);
        resetForm.append(resetTitle,resetField,confirmField,resetActions,resetFeedback);
        resetButton.onclick=()=>{
          const showing=resetForm.classList.contains('hide');
          resetForm.classList.toggle('hide',!showing);
          if(showing) resetInput.focus();
          else {resetForm.reset();resetFeedback.textContent='';}
        };
        resetCancel.onclick=()=>{resetForm.reset();resetFeedback.textContent='';resetForm.classList.add('hide');};
        resetForm.onsubmit=async event=>{
          event.preventDefault();
          if (resetInput.value!==confirmInput.value) {
            resetFeedback.textContent='Lösenorden är inte lika.';return;
          }
          if (!confirm('Återställ lösenordet för '+m.name+'? Medlemmen loggas ut från andra enheter.')) return;
          resetSave.disabled=true;
          resetFeedback.textContent='Sparar nytt lösenord …';
          try {
            await api('/admin/members/'+m.id+'/reset-password','POST',{password:resetInput.value});
            resetForm.reset();
            resetFeedback.textContent='Lösenordet är ändrat. Meddela medlemmen det nya lösenordet privat.';
          } catch(err) {resetFeedback.textContent=err.message;}
          finally {resetSave.disabled=false;}
        };
      }
      card.append(header);
      const form = element('form','member-admin-form hide');
      const fields = {};
      function field(label,key,value,type='text') {
        const div = element('div','field');
        const id = 'admin-member-' + m.id + '-' + key;
        const l = element('label','',label); l.htmlFor=id;
        const input = document.createElement('input');
        input.id=id; input.type=type; input.value=value ?? '';
        input.required=true; input.maxLength=key==='email'?180:key==='username'?50:100;
        div.append(l,input);form.append(div);fields[key]=input;
      }
      field('Namn','name',m.name);
      field('Fastighet / hus','house',m.house);
      field('Användarnamn','username',m.username);
      field('E-postadress (inloggning)','email',m.email,'email');
      const statusWrap=element('div','field');
      const statusLabel=element('label','','Medlemsstatus');
      const statusSelect=document.createElement('select');
      for (const [value,label] of [['active','Aktiv'],['inactive','Inaktiv']]) {
        const option=document.createElement('option');option.value=value;option.textContent=label;
        statusSelect.append(option);
      }
      statusSelect.value=m.status;
      if (m.role === 'admin') {
        statusSelect.disabled=true;
        statusLabel.textContent='Medlemsstatus (administratör – kan inte inaktiveras)';
      }
      statusWrap.append(statusLabel,statusSelect);form.append(statusWrap);
      const actions=element('div','actions');
      const cancel=element('button','btn subtle','Avbryt');cancel.type='button';
      const save=element('button','btn','Spara');save.type='submit';
      const feedback=element('p','small');feedback.setAttribute('role','status');
      actions.append(cancel,save);form.append(actions,feedback);
      edit.onclick=()=>{form.classList.toggle('hide');};
      cancel.onclick=()=>form.classList.add('hide');
      form.onsubmit=async event=>{
        event.preventDefault();
        if (statusSelect.value === 'inactive' && m.status !== 'inactive' &&
            !confirm('Inaktivera '+m.name+'? Medlemmen loggas ut och kan inte logga in förrän kontot återaktiveras.')) return;
        save.disabled=true;feedback.textContent='Sparar …';
        try {
          await api('/admin/members/'+m.id,'PUT',{
            name:fields.name.value,house:fields.house.value,
            username:fields.username.value,email:fields.email.value,
            status:statusSelect.value
          });
          await loadAdminMembers();
          await loadMembers();
          if (String(m.id) === String(currentMember.id)) {
            const {member} = await api('/me');
            currentMember=member;showSession();
          }
        } catch(err) { feedback.textContent=err.message;save.disabled=false; }
      };
      card.append(form);
      if (resetForm) card.append(resetForm);
      host.append(card);
    }
  } catch(err) { $('adminMembersStatus').textContent=err.message; }
}

$('inviteForm').onsubmit = async event => {
  event.preventDefault();
  const button=$('inviteForm').querySelector('button[type="submit"]');
  const status=$('inviteStatus');
  status.textContent='Skickar inbjudan …'; button.disabled=true;
  try {
    const result=await api('/admin/invitations','POST',{email:$('inviteEmail').value});
    status.textContent=result.message;
    $('inviteForm').reset();
  } catch(err) {status.textContent=err.message;}
  finally {button.disabled=false;}
};

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
      throw new Error('Lösenordet godkändes, men sessionen sparades inte i webbläsaren. Kontrollera att sidan öppnas på lillachatten.se och att cookies tillåts. (' + verifyError.message + ')');
    }
    currentMember = confirmed.member;
    $('loginPassword').value = '';
    showSession();
    await loadAssociation();
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
// Association-wide text is kept in the association's own database.
function applyAssociation(association) {
  associationProfile = association;
  $('associationTitle').textContent = association.app_title;
  $('associationTagline').textContent = association.tagline;
  $('associationWelcome').textContent = association.welcome_title;
  $('associationWelcomeText').textContent = association.welcome_text;
  $('associationAbout').textContent = association.about_text;
  $('associationId').textContent = association.association_id;
  $('setupTabHint').classList.toggle('hide', association.configured || currentMember?.role !== 'admin');
  $('tabBar').classList.toggle('hide', !association.configured && currentMember?.role === 'admin');
  $('setupHeading').textContent = association.configured ? '' : 'Välkommen till Lillachatten';
  if (currentMember?.role === 'admin' && !association.configured) view('setup');
  document.title = association.app_title + ' · Vår mötesplats';
}
function fillAssociationForm() {
  if (!associationProfile) return;
  const m = {
    associationName:'association_name',associationAppTitle:'app_title',
    associationTaglineEdit:'tagline',associationWelcomeEdit:'welcome_title',
    associationWelcomeTextEdit:'welcome_text',associationAboutEdit:'about_text'
  };
  for (const [id,field] of Object.entries(m)) $(id).value = associationProfile[field] || '';
}
async function loadAssociation() {
  try { const result = await api('/association'); applyAssociation(result.association); }
  catch(error) { console.warn('Föreningsinställningar kan inte hämtas:', error.message); }
}
$('associationForm').onsubmit = async event => {
  event.preventDefault();
  const button = $('associationForm').querySelector('button[type="submit"]');
  const status = $('associationStatus');
  button.disabled = true; status.textContent = 'Sparar …';
  try {
    const result = await api('/admin/association','PUT',{
      association_name:$('associationName').value,
      app_title:$('associationAppTitle').value,
      tagline:$('associationTaglineEdit').value,
      welcome_title:$('associationWelcomeEdit').value,
      welcome_text:$('associationWelcomeTextEdit').value,
      about_text:$('associationAboutEdit').value
    });
    applyAssociation(result.association);
    status.textContent = 'Föreningens texter är sparade.';
  } catch(error) { status.textContent = error.message; }
  finally { button.disabled = false; }
};
$('setupForm').onsubmit=async event=>{
  event.preventDefault();
  const button=$('setupForm').querySelector('button[type=submit]');
  button.disabled=true;
  $('setupStatus').textContent='Sparar föreningens namn …';
  try {
    const result=await api('/admin/association/initialize','POST',{name:$('setupName').value.trim()});
    applyAssociation(result.association);
    $('setupStatus').textContent='Föreningen är skapad. Du kan nu skicka den första inbjudan.';
    view('admin');
  } catch(err){$('setupStatus').textContent=err.message;}
  finally{button.disabled=false;}
};
loadAssociation();

(async function init() {
  // Avoid an initial /me request overwriting a successful manual login.
  const initialRequest = api('/me');
  try {
    const result = await initialRequest;
    if (currentMember) return;
    currentMember = result.member;
    showSession();
    await loadAssociation();
    view('feed');
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
