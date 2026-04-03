/* CloudPress — script.js */
'use strict';

const $ = (s, c = document) => c.querySelector(s);
const $$ = (s, c = document) => Array.from(c.querySelectorAll(s));

/* ── Custom Cursor ──────────────────────── */
(function () {
  const cur = $('#cursor');
  const fol = $('#cursorFollower');
  if (!cur || window.matchMedia('(max-width:700px)').matches) return;

  let mx = 0, my = 0, fx = 0, fy = 0;

  document.addEventListener('mousemove', e => {
    mx = e.clientX; my = e.clientY;
    cur.style.left = mx + 'px';
    cur.style.top  = my + 'px';
  });

  (function tick() {
    fx += (mx - fx) * 0.13;
    fy += (my - fy) * 0.13;
    fol.style.left = fx + 'px';
    fol.style.top  = fy + 'px';
    requestAnimationFrame(tick);
  })();
})();

/* ── Header scroll ──────────────────────── */
(function () {
  const h = $('#header');
  if (!h) return;
  const fn = () => h.classList.toggle('scrolled', window.scrollY > 36);
  window.addEventListener('scroll', fn, { passive: true });
  fn();
})();

/* ── Mobile burger ──────────────────────── */
(function () {
  const btn = $('#burger');
  const nav = $('#nav');
  if (!btn || !nav) return;

  btn.addEventListener('click', () => {
    const open = nav.classList.toggle('open');
    btn.setAttribute('aria-expanded', open);
    const [s1, , s3] = btn.querySelectorAll('span');
    btn.querySelectorAll('span')[1].style.opacity = open ? '0' : '';
    s1.style.transform = open ? 'rotate(45deg) translate(5px,5px)' : '';
    s3.style.transform = open ? 'rotate(-45deg) translate(5px,-5px)' : '';
  });

  $$('.nav a').forEach(a => a.addEventListener('click', () => {
    nav.classList.remove('open');
    btn.querySelectorAll('span').forEach(s => { s.style.transform = ''; s.style.opacity = ''; });
  }));
})();

/* ── Reveal on scroll ───────────────────── */
(function () {
  const els = $$('.reveal');
  if (!els.length) return;
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('in'); });
  }, { threshold: 0.1, rootMargin: '0px 0px -36px 0px' });
  els.forEach(el => io.observe(el));
})();

/* ── Spec bar animation ─────────────────── */
(function () {
  const fills = $$('.spec-fill');
  if (!fills.length) return;
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.style.width = e.target.dataset.w + '%';
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.4 });
  fills.forEach(el => io.observe(el));
})();

/* ── Counter animation ──────────────────── */
(function () {
  const els = $$('.count');
  if (!els.length) return;
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      const el = e.target;
      const target = parseFloat(el.dataset.target);
      const dec = parseInt(el.dataset.dec || '0');
      const dur = 1800;
      const start = performance.now();

      (function tick(now) {
        const p = Math.min((now - start) / dur, 1);
        const eased = 1 - Math.pow(1 - p, 4);
        el.textContent = (eased * target).toFixed(dec);
        if (p < 1) requestAnimationFrame(tick);
      })(performance.now());

      io.unobserve(el);
    });
  }, { threshold: 0.5 });
  els.forEach(el => io.observe(el));
})();

/* ── Billing toggle ─────────────────────── */
(function () {
  const btn = $('#billingTog');
  const lblMo = $('#lblMo');
  const lblYr = $('#lblYr');
  if (!btn) return;

  let annual = false;

  btn.addEventListener('click', () => {
    annual = !annual;
    btn.classList.toggle('on', annual);
    btn.setAttribute('aria-pressed', annual);
    lblMo.classList.toggle('on', !annual);
    lblYr.classList.toggle('on', annual);

    $$('.pnum').forEach(el => {
      const from = parseFloat(el.textContent.replace(/,/g, ''));
      const to = annual ? parseFloat(el.dataset.yr) : parseFloat(el.dataset.mo);
      animNum(el, from, to);
    });
  });

  // set initial active
  lblMo.classList.add('on');

  function animNum(el, from, to) {
    const dur = 380;
    const s = performance.now();
    (function tick(now) {
      const p = Math.min((now - s) / dur, 1);
      const v = from + (to - from) * (1 - Math.pow(1 - p, 3));
      el.textContent = Math.round(v).toLocaleString('ko-KR');
      if (p < 1) requestAnimationFrame(tick);
    })(performance.now());
  }
})();

/* ── FAQ accordion ──────────────────────── */
(function () {
  $$('.faq-item').forEach(item => {
    item.querySelector('.faq-q').addEventListener('click', () => {
      const wasOpen = item.classList.contains('open');
      $$('.faq-item').forEach(i => i.classList.remove('open'));
      if (!wasOpen) item.classList.add('open');
    });
  });
})();

/* ── Smooth scroll ──────────────────────── */
(function () {
  $$('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const id = a.getAttribute('href').slice(1);
      if (!id) return;
      const target = document.getElementById(id);
      if (!target) return;
      e.preventDefault();
      const hh = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--hh')) || 68;
      window.scrollTo({ top: target.getBoundingClientRect().top + scrollY - hh - 12, behavior: 'smooth' });
    });
  });
})();

/* ── Active nav on scroll ───────────────── */
(function () {
  const sections = $$('section[id]');
  const links = $$('.nav a');
  if (!sections.length || !links.length) return;
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        links.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + e.target.id));
      }
    });
  }, { rootMargin: '-40% 0px -55% 0px' });
  sections.forEach(s => io.observe(s));
})();

/* ── Toast helper ───────────────────────── */
function toast(msg) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 2800);
}

/* ── Demo CTA clicks ────────────────────── */
$$('a.btn[href="#"]').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    toast('🚀 베타 신청이 완료되었습니다!');
  });
});

/* ── Parallax orbs ──────────────────────── */
(function () {
  if (window.matchMedia('(prefers-reduced-motion:reduce)').matches) return;
  if (window.matchMedia('(max-width:700px)').matches) return;
  const orbs = $$('.orb');
  window.addEventListener('scroll', () => {
    const y = scrollY;
    orbs.forEach((o, i) => { o.style.transform = `translateY(${y * (.1 + i * .06)}px)`; });
  }, { passive: true });
})();

/* ── Load progress bar ──────────────────── */
(function () {
  const bar = document.createElement('div');
  Object.assign(bar.style, {
    position: 'fixed', top: '0', left: '0', zIndex: '9999',
    height: '2px', width: '0%',
    background: 'linear-gradient(to right,#f97316,#ec4899)',
    transition: 'width .25s ease', pointerEvents: 'none',
  });
  document.body.appendChild(bar);
  let w = 0;
  const iv = setInterval(() => {
    w += Math.random() * 18;
    if (w > 88) { clearInterval(iv); w = 88; }
    bar.style.width = w + '%';
  }, 180);
  window.addEventListener('load', () => {
    clearInterval(iv);
    bar.style.width = '100%';
    setTimeout(() => { bar.style.opacity = '0'; setTimeout(() => bar.remove(), 400); }, 250);
  });
})();

/* ── Keyboard: Escape closes nav ────────── */
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const nav = $('#nav');
    if (nav && nav.classList.contains('open')) nav.classList.remove('open');
  }
});

/* ── Reduce motion ──────────────────────── */
if (window.matchMedia('(prefers-reduced-motion:reduce)').matches) {
  document.documentElement.style.setProperty('--tr', '.01ms');
  $$('.orb,.bar,.badge-dot,.s-dot,.scroll-line').forEach(el => el.style.animation = 'none');
}
