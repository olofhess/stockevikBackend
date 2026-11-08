'use strict';
const $ = id => document.getElementById(id);
async function api(url, opts) {
  const r = await fetch(url, {credentials:'same-origin',...opts});
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.error || `Serverfel (${r.status})`);
  return data;
}
(async()=>{
  try {
    const me=await api('/api/me');
    if(me.member?.role!=='admin') throw new Error('Bara administratörer får skicka inbjudningar.');
    const {groups}=await api('/api/my-admin-groups');
    if(!groups?.length) throw new Error('Ingen administrerad grupp finns.');
    for(const g of groups){const o=document.createElement('option');o.value=g.id;o.textContent=g.group_name;$('group').append(o);}
  } catch(e) {$('status').textContent=e.message;$('send').disabled=true;}
})();
$('inviteForm').addEventListener('submit', async e=>{
 e.preventDefault();$('send').disabled=true;$('status').textContent='Skickar…';
 try{
  const result=await api(`/api/groups/${encodeURIComponent($('group').value)}/invitations`,{
   method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({email:$('email').value.trim()})
  });
  $('status').textContent=result.message || 'Inbjudan skickad.';
  $('email').value='';
 }catch(err){$('status').textContent=err.message;}
 finally{$('send').disabled=false;}
});
