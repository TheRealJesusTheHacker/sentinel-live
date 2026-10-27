/* Design pass 2026-10-25: shared motion, hand-rolled, dependency-free.
   Reveal-on-scroll (.rv / .rvf) is progressive enhancement — content is
   only hidden when JS is live (html.js, set in <head>) AND the visitor
   has not asked for reduced motion; the CSS reduced-motion block also
   forces everything visible. Motion is opacity/transform only, so
   layout never shifts. SSG.countUp animates a numeral to its target
   (used by the live counters); with reduced motion it sets the final
   value immediately. */
window.SSG = window.SSG || {};
SSG.reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
SSG.countUp = function (el, target, fmt) {
  if (!el) return;
  fmt = fmt || function (n) { return Math.round(n).toLocaleString('en-US'); };
  if (SSG.reduced || !isFinite(target)) { el.textContent = fmt(target); return; }
  var t0 = null, dur = 900;
  function step(ts) {
    if (!t0) t0 = ts;
    var p = Math.min(1, (ts - t0) / dur), e = 1 - Math.pow(1 - p, 3);
    el.textContent = fmt(target * e);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
};
(function () {
  var els = Array.prototype.slice.call(document.querySelectorAll('.rv, .rvf'));
  if (!els.length) return;
  if (SSG.reduced || !('IntersectionObserver' in window)) {
    els.forEach(function (el) { el.classList.add('in'); });
    return;
  }
  /* IntersectionObserver is the primary path; a position sweep on
     scroll backs it up so ANY scroll style — wheel, touch, keyboard
     jumps, anchor glides, programmatic scrolls fighting a CSS
     scroll-behavior — still reveals everything it passes. (Probed
     2026-10-25: smooth-glide retargeting could starve the observer;
     the sweep cannot be starved, it reads final positions.) */
  var pending = els.slice();
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (en.isIntersecting) reveal(en.target);
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -6% 0px' });
  function reveal(el) {
    el.classList.add('in');
    io.unobserve(el);
    var i = pending.indexOf(el);
    if (i >= 0) pending.splice(i, 1);
  }
  function sweep() {
    var line = window.innerHeight * 0.96;
    pending.slice().forEach(function (el) {
      if (el.getBoundingClientRect().top < line) reveal(el);
    });
  }
  var queued = false;
  window.addEventListener('scroll', function () {
    if (queued) return;
    queued = true;
    requestAnimationFrame(function () { queued = false; sweep(); });
  }, { passive: true });
  window.addEventListener('resize', sweep);
  els.forEach(function (el) { io.observe(el); });
  sweep();
  setTimeout(sweep, 1200);
})();
