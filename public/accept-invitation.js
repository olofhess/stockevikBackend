'use strict';
const $=id=>document.getElementById(id);
const token=new URLSearchParams(location.hash.slice(1)).get('token')||'';
// Keep token in memory only and remove it from browser history once loaded.
history.replaceState(null,'',location.pathname);
let email='';
async function api(path,body){const response=await fetch('/api/invitations/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'});const data=await response.json().catch(()=>({}));if(!response.ok)throw Error(data.error||'Ett fel uppstod.');return data;}
function show(id){for(const section of ['loading','decision','signup','done'])$(section).classList.toggle('hide',section!==id);$('error').textContent='';}
(async()=>{try{const data=await api('preview',{token});email=data.email;$('emailInfo').textContent='Inbjudan gäller: '+email;show('decision');}catch(err){show('done');$('doneHeading').textContent='Inbjudan kan inte användas';$('doneText').textContent=err.message;}})();
$('yes').onclick=()=>{show('signup');$('email').value=email;$('name').focus();};
$('no').onclick=async()=>{try{await api('decline',{token});show('done');$('doneHeading').textContent='Du har avstått';$('doneText').textContent='Din inbjudan är avslutad.';}catch(err){$('error').textContent=err.message;}};
$('signupForm').onsubmit=async e=>{e.preventDefault();$('error').textContent='';if($('password').value!==$('confirm').value){$('error').textContent='Lösenorden stämmer inte överens.';return;}const button=$('submit');button.disabled=true;try{const result=await api('accept',{token,name:$('name').value,house:$('house').value,password:$('password').value});show('done');$('doneHeading').textContent='Välkommen till Lillachatten!';$('doneText').textContent='Din registrering är klar. Du går nu direkt till inloggning.';$('loginLink').classList.remove('hide');const target='/?registered='+encodeURIComponent(result.email);location.replace(target);}catch(err){$('error').textContent=err.message;}finally{button.disabled=false;}};
