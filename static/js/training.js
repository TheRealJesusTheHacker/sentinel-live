(function(){
  var ITEMS = [
    {
      kind: "Email", fromName: "QuickBooks Billing",
      fromAddr: "billing@quickbooks.intuit.com",
      subject: "Your receipt for payment #4471",
      body: "Your monthly payment of $64.99 was processed. The receipt is attached to this message and is always available in your account under Settings, then Billing. No action is needed.",
      answer: "legit",
      why: "The sender address is the company's real domain, there is no link pushing you anywhere, no deadline, and the message asks for nothing. Receipts that simply inform — and that you can verify by signing in the normal way — read like this."
    },
    {
      kind: "Email", fromName: "Microsoft Account Team",
      fromAddr: "account-security@micros0ft-verify.example",
      subject: "URGENT: Your account will be locked in 1 hour",
      body: "We detected unusual sign-in activity. Your account will be permanently locked within 1 hour unless you verify your identity now. Click the link and enter your password and the code from your phone to avoid losing access.",
      answer: "phish",
      why: "Three tells stacked: the sender domain swaps a letter for a zero (micros0ft, on a made-up suffix), the one-hour deadline exists to stop you thinking, and it asks you to hand over both a password AND a sign-in code — the code is the keys to the account, and no real sign-in page you reach from an email will ever need it. Go to the account yourself, never from this link."
    },
    {
      kind: "Text message", fromName: "Delivery notice",
      fromAddr: "+1 (555) 014-2280",
      subject: "Package held",
      body: "USPS: Your package is held at the depot due to an incomplete address. Update your details within 12 hours to avoid return: [link to usps-redelivery.example]",
      answer: "phish",
      why: "A carrier you may not even be expecting, a short deadline, and a link to a look-alike address that is not the carrier's real domain. Real delivery problems are solved on the carrier's own site or app — typed by you — or at the counter, never from a texted link asking for details."
    },
    {
      kind: "Email", fromName: "Dana — Office Manager",
      fromAddr: "dana@yourcompany-kc.example",
      subject: "Quick favor — gift cards",
      body: "I'm stuck in a meeting and need you to grab six $100 gift cards for a client thank-you today. Keep it between us until the announcement, send me the card numbers when you have them, and I'll reimburse you tonight. — Dana",
      answer: "phish",
      why: "The classic boss-impersonation play: urgency, secrecy, and payment in gift cards — money that cannot be pulled back. The tell that matters most is the request itself, not the address: no real manager needs card numbers over email. A ten-second call or walk down the hall settles it, which is exactly what the secrecy is designed to prevent."
    },
    {
      kind: "Email", fromName: "Your Bank — Statements",
      fromAddr: "statements@alerts.yourbank.example",
      subject: "Your October statement is ready",
      body: "Your monthly statement is ready to view. Sign in the way you normally do — through the bank's app or by typing the bank's address yourself — and look under Statements. For your security, this email contains no links and we will never ask for your password by email.",
      answer: "legit",
      why: "It tells you to arrive the safe way — through the app or an address you type — carries no link at all, asks for nothing, and sets no deadline. Messages that respect the go-around rule read like this. (The addresses in this training are mock-ups; the shape is what to learn.)"
    },
    {
      kind: "Email", fromName: "IT Department",
      fromAddr: "helpdesk@company-mail-verify.example",
      subject: "New payroll form — action required by Friday",
      body: "Payroll is moving to a new system. Every employee must complete the attached direct-deposit update form and return it by email before Friday, or the next paycheck will be delayed.",
      answer: "phish",
      why: "A bank-account form, returned by email, against a payday deadline — that combination should stop anyone cold. Bank details travel through the payroll system itself, in person or in the system you already use, never as an email attachment. The vague outside sending domain is the second tell."
    }
  ];
  var list = document.getElementById('ph-list');
  var scoreEl = document.getElementById('ph-score');
  var answered = 0, right = 0;
  ITEMS.forEach(function(it, idx){
    var card = document.createElement('article');
    card.className = 'ph-card';
    var mock = document.createElement('div');
    mock.className = 'ph-mock';
    mock.setAttribute('aria-label', 'Training sample ' + (idx + 1));
    mock.innerHTML = '<p class="ph-kind"></p><p class="ph-from"></p><p class="ph-subj"></p><p class="ph-body"></p>';
    mock.querySelector('.ph-kind').textContent = it.kind + ' — training sample, not a real message';
    mock.querySelector('.ph-from').textContent = 'From: ' + it.fromName + ' <' + it.fromAddr + '>';
    mock.querySelector('.ph-subj').textContent = 'Subject: ' + it.subject;
    mock.querySelector('.ph-body').textContent = it.body;
    var btns = document.createElement('div');
    btns.className = 'tool-row';
    var bL = document.createElement('button');
    bL.type = 'button'; bL.textContent = 'Legit';
    var bP = document.createElement('button');
    bP.type = 'button'; bP.textContent = 'Phish';
    var why = document.createElement('p');
    why.className = 'ph-why'; why.hidden = true;
    function judge(pick){
      if (!why.hidden) return;
      bL.disabled = true; bP.disabled = true;
      answered++;
      var correct = pick === it.answer;
      if (correct) right++;
      why.textContent = (correct ? 'Right call. ' : 'It was a ' + (it.answer === 'phish' ? 'phish' : 'legit message') + '. ') + it.why;
      why.hidden = false;
      scoreEl.textContent = 'Score: ' + right + ' of ' + answered + ' answered.' +
        (answered === ITEMS.length ? ' Round complete — the tells are listed below the round, any time you want a refresher.' : '');
    }
    bL.addEventListener('click', function(){ judge('legit'); });
    bP.addEventListener('click', function(){ judge('phish'); });
    btns.appendChild(bL); btns.appendChild(bP);
    card.appendChild(mock); card.appendChild(btns); card.appendChild(why);
    list.appendChild(card);
  });
})();
