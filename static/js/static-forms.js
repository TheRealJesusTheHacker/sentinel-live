(function(){
  var form=document.getElementById('ticket-form');
  if(!form)return;
  var status=document.getElementById('tf-status');
  var button=document.getElementById('tf-submit');
  function tsToken(){var i=form.querySelector('input[name="cf-turnstile-response"]');return i?i.value:'';}
  function tsReset(){if(window.turnstile){try{turnstile.reset();}catch(e){}}}
  form.addEventListener('submit',function(ev){
    ev.preventDefault();
    status.textContent='Sending\u2026';
    button.disabled=true;
    var payload={
      name:document.getElementById('tf-name').value.trim(),
      email:document.getElementById('tf-email').value.trim(),
      phone:document.getElementById('tf-phone').value.trim(),
      category:document.getElementById('tf-category').value,
      priority:document.getElementById('tf-priority').value,
      subject:document.getElementById('tf-subject').value.trim(),
      message:document.getElementById('tf-message').value.trim(),
      'cf-turnstile-response':tsToken()
    };
    fetch('/api/ticket',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
    .then(function(res){return res.json().catch(function(){return{};}).then(function(data){return{ok:res.ok,data:data};});})
    .then(function(r){
      button.disabled=false;
      tsReset();
      if(r.ok&&r.data.ok){
        form.reset();
        status.textContent='Ticket #'+r.data.ticket_id+' is open. We\u2019ll get back to you at the email you gave us \u2014 keep that number if you need to reference it.';
      }else{
        status.textContent=((r.data&&r.data.detail)?r.data.detail+' ':'Something went wrong sending that. ')+'You can also email Sentinelsafeguard@outlook.com or call 816-533-8418.';
      }
    })
    .catch(function(){
      button.disabled=false;
      tsReset();
      status.textContent='That did not go through. Email Sentinelsafeguard@outlook.com or call 816-533-8418 and we\u2019ll take it from there.';
    });
  });
})();

/* Design pass 2026-10-25: reveal-on-scroll — progressive enhancement,
   hidden only under html.js, everything visible under reduced motion. */
(function(){
  var els=Array.prototype.slice.call(document.querySelectorAll('.rv'));
  if(!els.length)return;
  if(window.matchMedia('(prefers-reduced-motion: reduce)').matches||!('IntersectionObserver' in window)){
    els.forEach(function(el){el.classList.add('in');});return;
  }
  var pending=els.slice();
  var io=new IntersectionObserver(function(entries){
    entries.forEach(function(en){if(en.isIntersecting)reveal(en.target);});
  },{threshold:0.1,rootMargin:'0px 0px -6% 0px'});
  function reveal(el){el.classList.add('in');io.unobserve(el);var i=pending.indexOf(el);if(i>=0)pending.splice(i,1);}
  function sweep(){var line=window.innerHeight*0.96;pending.slice().forEach(function(el){if(el.getBoundingClientRect().top<line)reveal(el);});}
  var queued=false;
  window.addEventListener('scroll',function(){if(queued)return;queued=true;requestAnimationFrame(function(){queued=false;sweep();});},{passive:true});
  window.addEventListener('resize',sweep);
  els.forEach(function(el){io.observe(el);});
  sweep();
  setTimeout(sweep,1200);
})();
