(function(){
  var FIX = {
    router: "Change the router/firewall admin password to a long, unique passphrase, and write down where it is kept. The shipped password is printed in a public manual.",
    updates: "Turn on automatic updates for every computer, browser, and the router/firewall itself — then check once that they really are on.",
    backups: "Set up backups that run on their own, keep one copy an attacker in your network cannot reach, and restore a few files as a real test. A backup you have never restored is a hope, not a backup.",
    mfa: "Turn on multi-factor authentication for email and banking first, then every account that matters — for every person, not just the owner.",
    passwords: "Get a password manager, put every work account in it, and change any password that is reused anywhere. Long passphrases beat short complicated ones — the <a href=\"/tools\">tools page</a> makes them.",
    wifi: "Put guests and personal phones on their own Wi-Fi network, separate from work computers and records. Most routers can do this in settings today.",
    locks: "Set screens to lock after a few idle minutes, and lock the room or closet that holds the router and network gear. Stop sharing door codes.",
    training: "Run the free practice round on the <a href=\"/training/phishing\">phishing training page</a> with everyone who opens email — and make “stop and ask” the house rule.",
    antivirus: "Check every single computer — including the back-office one — for protective software that is installed, running, and current.",
    plan: "Write the one-page plan: who to call first (Sentinel's number is 816-533-8418), what to unplug, what not to touch. Put it where people can find it at 9 a.m. on a bad day."
  };
  var LABEL = {
    router: "Router & firewall password", updates: "Automatic updates",
    backups: "Backups, restore-tested", mfa: "Multi-factor authentication",
    passwords: "Unique passwords", wifi: "Separate guest Wi-Fi",
    locks: "Locks & screen locks", training: "Spotting phishing",
    antivirus: "Protective software", plan: "Incident plan"
  };
  var POINTS = { yes: 10, partly: 5, no: 0, unsure: 0 };
  var form = document.getElementById('assess-form');
  var status = document.getElementById('assess-status');
  form.addEventListener('submit', function(ev){
    ev.preventDefault();
    var keys = Object.keys(FIX), score = 0, gaps = [], missing = [];
    keys.forEach(function(k){
      var picked = form.querySelector('input[name="q-' + k + '"]:checked');
      if (!picked) { missing.push(k); return; }
      score += POINTS[picked.value];
      if (picked.value !== 'yes') gaps.push({k: k, v: picked.value});
    });
    if (missing.length) {
      status.textContent = 'Answer every question to get a score — ' +
        missing.length + ' still open. “Not sure” counts as an answer (and as a gap worth closing).';
      var first = form.querySelector('fieldset[data-key="' + missing[0] + '"]');
      if (first) first.scrollIntoView({behavior: 'smooth', block: 'center'});
      return;
    }
    status.textContent = '';
    // Biggest risks first: "no" and "not sure" (0 points) ahead of "partly".
    gaps.sort(function(a, b){ return POINTS[a.v] - POINTS[b.v]; });
    var list = document.getElementById('assess-list');
    list.innerHTML = '';
    gaps.forEach(function(g){
      var li = document.createElement('li');
      li.innerHTML = '<strong>' + LABEL[g.k] + ':</strong> ' + FIX[g.k];
      list.appendChild(li);
    });
    document.getElementById('assess-clean').hidden = gaps.length !== 0;
    document.getElementById('assess-score').textContent = score;
    var verdict = document.getElementById('assess-verdict');
    if (score >= 90) verdict.textContent = 'The basics are genuinely in place. What remains is keeping them true as people and systems change.';
    else if (score >= 65) verdict.textContent = 'The foundation is there, with a few open doors. The checklist below is ordered so the widest gaps close first.';
    else if (score >= 40) verdict.textContent = 'Some protection is in place, but the gaps below are the ones real attacks walk through. They are all closable — most in an afternoon each.';
    else verdict.textContent = 'Most of the basics are open right now. That is fixable, and it is fixable in order: start at the top of the checklist, one item at a time.';
    var results = document.getElementById('results');
    results.hidden = false;
    results.scrollIntoView({behavior: 'smooth', block: 'start'});
  });
})();
