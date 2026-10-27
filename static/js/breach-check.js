/* BREACH-CHECK-2026-10-27: the Breach Check page's two tools.
   Email leg: POST the address to our own /api/breach-check/email
   and render the JSON cards with textContent only — breach names,
   dates, and data types are UPSTREAM strings, so they are never
   inserted as markup.
   Password leg: SHA-1 the password HERE, in the browser, with
   crypto.subtle; send ONLY the first 5 hex characters (the
   prefix) to /api/breach-check/password; find our own suffix in
   the returned list locally. The full password and the full hash
   never leave this page. */
(function () {
  function tsToken(form) {
    var i = form.querySelector('input[name="cf-turnstile-response"]');
    return i ? i.value : '';
  }
  function tsReset() {
    if (window.turnstile) { try { window.turnstile.reset(); } catch (e) {} }
  }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function postJson(path, payload) {
    return fetch(path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        return {ok: res.ok, data: data};
      });
    });
  }

  /* ------------------------------------------------ email leg */
  var emailForm = document.getElementById('bc-email-form');
  if (emailForm) {
    var emailStatus = document.getElementById('bc-email-status');
    var emailButton = document.getElementById('bc-email-submit');
    var emailResults = document.getElementById('bc-email-results');
    emailForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var email = document.getElementById('bc-email').value.trim();
      emailStatus.textContent = 'Checking…';
      emailButton.disabled = true;
      while (emailResults.firstChild) emailResults.removeChild(emailResults.firstChild);
      postJson('/api/breach-check/email', {
        email: email,
        'cf-turnstile-response': tsToken(emailForm)
      }).then(function (r) {
        emailButton.disabled = false;
        tsReset();
        if (!r.ok) {
          emailStatus.textContent = (r.data && r.data.detail) ||
            'The lookup did not go through — please try again.';
          return;
        }
        emailStatus.textContent = '';
        if (!r.data.found) {
          emailResults.appendChild(el('p', 'breach-clean',
            'No known public breaches found for this address in the ' +
            'data XposedOrNot holds. That is good news — keep a unique ' +
            'password on the account and multi-factor authentication ' +
            'on, and it stays that way.'));
          return;
        }
        var breaches = r.data.breaches || [];
        emailResults.appendChild(el('p', 'breach-found',
          'This address appears in ' + breaches.length +
          (breaches.length === 1 ? ' known public breach.' : ' known public breaches.') +
          ' Work through the “What to do now” list below the tools.'));
        if (!r.data.metadata_available) {
          emailResults.appendChild(el('p', 'dim',
            'Breach details beyond the name are unavailable right now, ' +
            'so these cards show names only.'));
        }
        breaches.forEach(function (b) {
          var card = el('article', 'breach-card');
          card.appendChild(el('h3', null, b.name || 'Unnamed breach'));
          if (b.metadata) {
            var meta = [];
            if (b.date) meta.push('Breached: ' + b.date);
            if (b.domain) meta.push('Site: ' + b.domain);
            if (meta.length) card.appendChild(el('p', 'breach-meta', meta.join(' · ')));
            if (b.exposed_data && b.exposed_data.length) {
              card.appendChild(el('p', null,
                'Exposed data: ' + b.exposed_data.join(', ')));
            } else {
              card.appendChild(el('p', null,
                'Data types weren\u2019t published for this breach.'));
            }
            if (b.password_risk) {
              card.appendChild(el('p', null, 'Password risk: ' + b.password_risk));
            }
            if (b.exposed_records != null) {
              card.appendChild(el('p', null,
                'Records exposed: ' + Number(b.exposed_records).toLocaleString('en-US')));
            }
          } else {
            card.appendChild(el('p', 'dim',
              'Details for this breach weren\u2019t available — name only.'));
          }
          card.appendChild(el('p', 'breach-source', 'Source: XposedOrNot'));
          emailResults.appendChild(card);
        });
      }).catch(function () {
        emailButton.disabled = false;
        tsReset();
        emailStatus.textContent = 'That did not go through — please try again.';
      });
    });
  }

  /* --------------------------------------------- password leg */
  function sha1Hex(text) {
    var bytes = new TextEncoder().encode(text);
    return crypto.subtle.digest('SHA-1', bytes).then(function (buf) {
      var view = new Uint8Array(buf);
      var hex = '';
      for (var i = 0; i < view.length; i++) {
        hex += ('0' + view[i].toString(16)).slice(-2);
      }
      return hex.toUpperCase();
    });
  }
  var pwForm = document.getElementById('bc-password-form');
  if (pwForm) {
    var pwStatus = document.getElementById('bc-password-status');
    var pwButton = document.getElementById('bc-password-submit');
    var pwResults = document.getElementById('bc-password-results');
    pwForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var input = document.getElementById('bc-password');
      var password = input.value;
      if (!password) {
        pwStatus.textContent = 'Type a password to check first.';
        return;
      }
      pwStatus.textContent = 'Checking…';
      pwButton.disabled = true;
      while (pwResults.firstChild) pwResults.removeChild(pwResults.firstChild);
      sha1Hex(password).then(function (hash) {
        password = '';
        input.value = '';
        var prefix = hash.slice(0, 5);
        var suffix = hash.slice(5);
        return postJson('/api/breach-check/password', {
          prefix: prefix,
          'cf-turnstile-response': tsToken(pwForm)
        }).then(function (r) {
          pwButton.disabled = false;
          tsReset();
          if (!r.ok) {
            pwStatus.textContent = (r.data && r.data.detail) ||
              'The check did not go through — please try again.';
            return;
          }
          pwStatus.textContent = '';
          var count = 0;
          (r.data.suffixes || []).forEach(function (line) {
            var parts = String(line).split(':');
            if (parts[0] === suffix) count = parseInt(parts[1], 10) || 0;
          });
          if (count > 0) {
            pwResults.appendChild(el('p', 'breach-found',
              'This password has appeared about ' +
              count.toLocaleString('en-US') +
              ' times in breach corpora. Do not use it anywhere — ' +
              'change it anywhere it is in use, and see “What to do ' +
              'now” below.'));
          } else {
            pwResults.appendChild(el('p', 'breach-clean',
              'This password was not found in the breach corpora ' +
              'checked. That does not make a short or reused password ' +
              'safe — length and uniqueness still do the real work.'));
          }
        });
      }).catch(function () {
        pwButton.disabled = false;
        tsReset();
        pwStatus.textContent = 'That did not go through — please try again.';
      });
    });
  }
})();
