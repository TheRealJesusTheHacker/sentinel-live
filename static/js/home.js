(function(){
  var form=document.getElementById('contact-form');
  if(!form)return;
  var status=document.getElementById('cf-status');
  var button=document.getElementById('cf-submit');
  function tsToken(){var i=form.querySelector('input[name="cf-turnstile-response"]');return i?i.value:'';}
  function tsReset(){if(window.turnstile){try{turnstile.reset();}catch(e){}}}
  form.addEventListener('submit',function(ev){
    ev.preventDefault();
    status.textContent='Sending\u2026';
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
        status.textContent='Got it \u2014 your message is in. We\u2019ll get back to you at the email you gave us.';
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

(function(){
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function fmt(n){return Number(n||0).toLocaleString('en-US');}
  function countUp(el,target,render){
    if(el._counted||window.matchMedia('(prefers-reduced-motion: reduce)').matches){el.textContent=render(target);return;}
    el._counted=true;
    var t0=null;
    function step(ts){if(!t0)t0=ts;var p=Math.min(1,(ts-t0)/900),e=1-Math.pow(1-p,3);el.textContent=render(Math.round(target*e));if(p<1)requestAnimationFrame(step);}
    requestAnimationFrame(step);
  }
  function load(){
    fetch('/api/threat-data').then(function(r){return r.json();}).then(function(d){
      countUp(document.getElementById('pv-threat-stat'),d.attacks_today,function(v){return fmt(v)+' attacks today · '+fmt(d.sources_today)+' sources';});
      var rows=(d.countries||[]).slice(0,3).map(function(c){return '<li><span>'+esc(c.code)+'</span><b>'+fmt(c.count)+' attacks</b></li>';}).join('');
      document.getElementById('pv-threat-list').innerHTML=rows||'<li>No data yet — retrying automatically.</li>';
    }).catch(function(){document.getElementById('pv-threat-stat').textContent='Live data unreachable — retrying.';});
    fetch('/api/geo-data').then(function(r){return r.json();}).then(function(g){
      document.getElementById('pv-geo-stat').textContent=(g.items||[]).length+' stories · '+(g.hotspots||[]).length+' hotspots mapped';
      var rows=(g.items||[]).slice(0,3).map(function(it){return '<li>'+(it.link?'<a href="'+esc(it.link)+'" target="_blank" rel="noopener">'+esc(it.title)+'</a>':esc(it.title))+'</li>';}).join('');
      document.getElementById('pv-geo-list').innerHTML=rows||'<li>No stories right now.</li>';
    }).catch(function(){document.getElementById('pv-geo-stat').textContent='Live data unreachable — retrying.';});
  }
  load();
  setInterval(load,60000);
})();

/* Design pass 2026-10-25: reveal-on-scroll for the marketing page.
   Progressive enhancement — elements are hidden only under html.js
   (set in <head>) and every one is revealed as it enters the
   viewport; reduced-motion visitors get everything, still, at once. */
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
