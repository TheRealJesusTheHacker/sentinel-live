(function(){
  var splash=document.getElementById('sentinel-splash');
  if(!splash)return;
  var storageKey='sentinel-splash-welcome-v1';
  var alreadySeen=false;
  try{
    alreadySeen=window.sessionStorage.getItem(storageKey)==='1';
    if(!alreadySeen)window.sessionStorage.setItem(storageKey,'1');
  }catch(e){}
  if(alreadySeen){splash.remove();return;}

  var root=document.documentElement;
  var body=document.body;
  var reduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var finished=false;
  var dismissTimer=0;
  var removeTimer=0;
  var hardTimer=0;

  function detach(){
    window.clearTimeout(dismissTimer);
    window.clearTimeout(removeTimer);
    window.clearTimeout(hardTimer);
    splash.removeEventListener('pointerdown',dismiss);
    splash.removeEventListener('click',dismiss);
    window.removeEventListener('keydown',dismiss,true);
  }
  function removeSplash(){
    if(finished)return;
    finished=true;
    detach();
    root.classList.remove('splash-lock');
    if(body)body.classList.remove('splash-lock');
    splash.remove();
  }
  function dismiss(){
    if(finished)return;
    splash.classList.add('is-exiting');
    removeTimer=window.setTimeout(removeSplash,reduced?90:350);
  }

  splash.hidden=false;
  root.classList.add('splash-lock');
  if(body)body.classList.add('splash-lock');
  splash.addEventListener('pointerdown',dismiss,{passive:true});
  splash.addEventListener('click',dismiss);
  window.addEventListener('keydown',dismiss,true);
  /* Retimed 2026-10-26 (owner feedback): the intro choreography is
     unchanged; the final clean hold is longer, so the fade begins at
     ~3.9s and the force-dismiss fallback sits at ~4.7s. */
  dismissTimer=window.setTimeout(dismiss,reduced?620:3900);
  /* Independent of every animation and transition: if anything in
     the visual sequence stalls, the visitor is released anyway. */
  hardTimer=window.setTimeout(removeSplash,reduced?1250:4700);
})();

/* Last-resort splash watchdog: this separate timer still runs if the
   entry controller above is interrupted after revealing the overlay. */
window.setTimeout(function(){
  var splash=document.getElementById('sentinel-splash');
  if(splash&&!splash.hidden){
    document.documentElement.classList.remove('splash-lock');
    if(document.body)document.body.classList.remove('splash-lock');
    splash.remove();
  }
},5500);
