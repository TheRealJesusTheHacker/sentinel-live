(function(){
  var form=document.getElementById('contact-form');
  if(!form)return;
  var status=document.getElementById('cf-status');
  var button=document.getElementById('cf-submit');
  function tsToken(){var i=form.querySelector('input[name="cf-turnstile-response"]');return i?i.value:'';}
  function tsReset(){if(window.turnstile){try{turnstile.reset();}catch(e){}}}
  form.addEventListener('submit',function(ev){
    ev.preventDefault();
    status.textContent='Sending…';
    button.disabled=true;
    var payload={
      name:document.getElementById('cf-name').value.trim(),
      email:document.getElementById('cf-email').value.trim(),
      subject:document.getElementById('cf-subject').value.trim(),
      service:document.getElementById('cf-service').value,
      pref_date:document.getElementById('cf-pref-date').value,
      pref_window:document.getElementById('cf-pref-window').value,
      message:document.getElementById('cf-message').value.trim(),
      'cf-turnstile-response':tsToken()
    };
    fetch('/api/contact',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
    .then(function(res){return res.json().catch(function(){return{};}).then(function(data){return{ok:res.ok,data:data};});})
    .then(function(r){
      button.disabled=false;
      tsReset();
      if(r.ok&&r.data.ok){
        form.reset();
        status.textContent='Got it — your message is in. We’ll get back to you at the email you gave us.';
      }else{
        status.textContent=((r.data&&r.data.detail)?r.data.detail+' ':'Something went wrong sending that. ')+'You can also email Sentinelsafeguard@outlook.com or call 816-533-8418.';
      }
    })
    .catch(function(){
      button.disabled=false;
      tsReset();
      status.textContent='That did not go through. Email Sentinelsafeguard@outlook.com or call 816-533-8418 and we’ll take it from there.';
    });
  });
})();
