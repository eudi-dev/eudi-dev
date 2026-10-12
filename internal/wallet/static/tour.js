(function () {
  'use strict';

  const DONE_KEY = 'eudi-dev-tour-done';
  const MARGIN = 16;
  const GAP = 12;
  const PAD = 6;

  const byId = (id) => document.getElementById(id);
  const visible = (el) => !!el && el.getClientRects().length > 0;
  const demo = () => !byId('demo-note').hidden;

  // A header link collapses into the menu on narrow screens. Its step then
  // points at the menu button.
  const TOURS = {
    overview: [
      {
        target: () => byId('offer-input'),
        title: 'Paste an offer or request',
        text: () => 'Paste a credential offer or a presentation request link and press Process.',
      },
      {
        target: () => byId('issue-btn'),
        title: 'Issue a credential yourself',
        text: () => 'Issue a credential with any type, claims and signing key. Import credential adds one you already have.',
      },
      {
        target: () => byId('actions-hint'),
        title: 'Try the demo issuer and verifier',
        text: () => 'No offer at hand? Get a credential from the demo issuer. Then present it to the demo verifier.',
      },
      {
        target: () => byId('credentials').querySelector('.credential-card') || byId('credentials'),
        title: 'Check your credentials',
        text: () => byId('credentials').querySelector('.credential-card')
          ? 'Badges show the status, expiry, signature and key binding of each credential. Use About for its description and Show to decode it.'
          : 'Credentials you receive show up here. Badges on each card show status, expiry, signature and key binding.',
      },
      {
        target: () => byId('activity-drawer'),
        title: 'Follow every exchange',
        text: () => 'Every request and response shows up in the activity log. Open a signed one in the decoder to check its header, payload and signature.',
      },
      {
        nav: 'trust-link',
        title: 'Set up trust',
        text: () => 'Download the trusted lists and CA certificates of this wallet. Configure them in your issuer or verifier.',
      },
      {
        nav: 'registrar-menu-toggle',
        title: 'Register your verifier or issuer',
        text: () => 'Register your verifier or issuer to get an access certificate and a registration certificate. The attestation catalogue describes each credential type.',
      },
      {
        nav: 'conformance-link',
        title: 'Choose how strict the wallet is',
        text: () => demo()
          ? 'See which checks this demo runs, such as strict mode, HAIP and ARF. Run your own wallet to change them.'
          : 'Pick debug mode to see what your issuer or verifier gets wrong, or strict mode to refuse it. You also switch HAIP and ARF checks on here.',
      },
      {
        nav: 'templates-link',
        title: 'Define your own credential types',
        text: () => 'Define a template with a type, claims and display. Then issue it with Issue credential.',
      },
      {
        nav: 'decoder-link',
        title: 'Decode a credential',
        text: () => 'Paste an SD-JWT, mdoc or JWT to see its contents and check its signature.',
      },
    ],
    news: [
      {
        nav: 'registrar-menu-toggle',
        title: 'Register your verifier or issuer',
        text: () => 'Open Relying parties to register your service. You get an access certificate and a registration certificate. The wallet tells you when your request asks for more than you registered.',
      },
      {
        nav: 'registrar-menu-toggle',
        title: 'Browse attestation types',
        text: () => 'The Attestation catalogue lists each credential type with its schemas, rulebook and trusted list.',
      },
      {
        nav: 'conformance-link',
        title: 'Check against the ARF',
        text: () => demo()
          ? 'This demo checks access and registration certificates as the ARF describes. The consent dialog lists every failed check.'
          : 'Switch on the ARF checks to test access and registration certificates. In debug mode the consent dialog lists every failed check.',
      },
      {
        nav: 'trust-link',
        title: 'Bring your own trust',
        text: () => 'Put your issuer\'s CA on one of the wallet\'s trusted lists, or add a list of your own.',
      },
      {
        nav: 'how-to-use-link',
        title: 'Follow the registrar walkthrough',
        text: () => 'The Registrar tab shows every step with curl, from the registration to a signed request.',
      },
    ],
  };

  function resolve(step) {
    if (!step.nav) {
      const el = step.target();
      return visible(el) ? { el: el, viaMenu: false } : null;
    }
    const link = byId(step.nav);
    if (!link || link.closest('[hidden]')) return null;
    if (visible(link)) return { el: link, viaMenu: false };
    const menu = byId('header-menu-toggle');
    return visible(menu) ? { el: menu, viaMenu: true } : null;
  }

  const root = byId('tour');
  const spot = byId('tour-spot');
  const card = byId('tour-card');
  const stepLabel = byId('tour-step');
  const title = byId('tour-title');
  const text = byId('tour-text');
  const back = byId('tour-back');
  const next = byId('tour-next');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  let steps = [];
  let index = 0;
  let current = null;
  let returnFocus = null;
  let frame = 0;

  function place() {
    frame = 0;
    if (!current) return;
    const vw = document.documentElement.clientWidth;
    const vh = window.innerHeight;
    const r = current.el.getBoundingClientRect();
    // A target taller than the window is clamped so the card still fits.
    const top = Math.max(r.top - PAD, 4);
    const bottom = Math.min(r.bottom + PAD, vh - 4);
    const left = Math.max(r.left - PAD, 4);
    const right = Math.min(r.right + PAD, vw - 4);
    Object.assign(spot.style, {
      top: top + 'px',
      left: left + 'px',
      width: Math.max(right - left, 0) + 'px',
      height: Math.max(bottom - top, 0) + 'px',
    });
    const cw = card.offsetWidth;
    const ch = card.offsetHeight;
    let cardTop;
    if (bottom + GAP + ch <= vh - MARGIN) cardTop = bottom + GAP;
    else if (top - GAP - ch >= MARGIN) cardTop = top - GAP - ch;
    else cardTop = vh - ch - MARGIN;
    const cardLeft = Math.min(Math.max(r.left, MARGIN), vw - cw - MARGIN);
    card.style.top = Math.max(cardTop, MARGIN) + 'px';
    card.style.left = Math.max(cardLeft, MARGIN) + 'px';
  }

  function schedule() {
    if (!frame) frame = requestAnimationFrame(place);
  }

  function show(i) {
    index = i;
    const step = steps[i];
    current = resolve(step);
    if (!current) {
      // A resize or a reload of the list can remove a target mid-tour.
      steps.splice(i, 1);
      if (steps.length === 0) return close();
      return show(Math.min(i, steps.length - 1));
    }
    stepLabel.textContent = 'Step ' + (i + 1) + ' of ' + steps.length;
    title.textContent = step.title;
    text.textContent = step.text() + (current.viaMenu ? ' Find it under Menu.' : '');
    back.hidden = i === 0;
    next.textContent = i === steps.length - 1 ? 'Done' : 'Next';
    if (document.activeElement === back && back.hidden) next.focus();
    current.el.scrollIntoView({ block: 'center', inline: 'nearest', behavior: reducedMotion.matches ? 'auto' : 'smooth' });
    place();
  }

  let tour = 'overview';

  function start(name, focusAfter) {
    tour = name;
    steps = TOURS[name].filter((step) => resolve(step));
    if (steps.length === 0) return;
    returnFocus = focusAfter || null;
    const links = byId('header-links');
    if (links.classList.contains('open')) byId('header-menu-toggle').click();
    root.hidden = false;
    document.addEventListener('scroll', schedule, true);
    window.addEventListener('resize', schedule);
    show(0);
    next.focus();
  }

  function close() {
    root.hidden = true;
    current = null;
    document.removeEventListener('scroll', schedule, true);
    window.removeEventListener('resize', schedule);
    const target = visible(returnFocus) ? returnFocus : byId('header-menu-toggle');
    if (visible(target)) target.focus();
  }

  function finish() {
    if (tour === 'news') {
      try { localStorage.setItem(DONE_KEY, '1'); } catch (e) { /* Storage may be unavailable in private browsing. */ }
      byId('news-tour').hidden = true;
    }
    close();
  }

  next.addEventListener('click', () => {
    if (index === steps.length - 1) finish();
    else show(index + 1);
  });
  back.addEventListener('click', () => { if (index > 0) show(index - 1); });
  byId('tour-close').addEventListener('click', close);

  root.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      close();
      return;
    }
    if (event.key === 'ArrowRight' && index < steps.length - 1) { event.preventDefault(); show(index + 1); return; }
    if (event.key === 'ArrowLeft' && index > 0) { event.preventDefault(); show(index - 1); return; }
    if (event.key !== 'Tab') return;
    const focusable = Array.from(card.querySelectorAll('button')).filter(visible);
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && (document.activeElement === first || !card.contains(document.activeElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || !card.contains(document.activeElement))) {
      event.preventDefault();
      first.focus();
    }
  });

  byId('howto-tour').addEventListener('click', () => {
    byId('howto-close').click();
    start('overview', byId('how-to-use-link'));
  });
  byId('news-tour').addEventListener('click', () => {
    byId('news-close').click();
    start('news', byId('news-link'));
  });
  try { if (localStorage.getItem(DONE_KEY) === '1') byId('news-tour').hidden = true; } catch (e) { /* Storage may be unavailable in private browsing. */ }
})();
