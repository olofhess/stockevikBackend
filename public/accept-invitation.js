'use strict';
const $ = id => document.getElementById(id);
const match=/^#token=([a-f0-9]{64})$/.exec(location.hash);
const token=match?.[1];
// Remove the secret from the visible URL and browser history immediately.
if(token) history.replaceState(null,'',location.pathname);
async function api(url,payload){
 const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
 const data=await r.json().catch(()=>({}));
 if(!r.ok) throw new Error(data.error || `Serverfel (${r.status})`);
 return data;
}
(async()=>{
 if(!token){$('description').textContent='Inbjudningslänken saknar en giltig kod.';return;}
 try{
  const invitation=await api('/api/invitations/preview',{token});
  $('description').textContent=`Du är inbjuden till ${invitation.groupName}.`;
  $('email').value=invitation.email;
  $('acceptForm').hidden=false;
 }catch(err){$('description').textContent=err.message;}
})();
$('acceptForm').addEventListener('submit',async e=>{
 e.preventDefault();$('accept').disabled=true;$('status').textContent='Skapar konto…';
 try{
  const result=await api('/api/invitations/accept',{
   token,name:$('name').value.trim(),house:$('house').value.trim(),password:$('password').value
  });
  $('acceptForm').hidden=true;
  $('status').textContent=result.message+' Gå till startsidan och logga in.';
 }catch(err){$('status').textContent=err.message;$('accept').disabled=false;}
});
