(function() {
  'use strict';

  // Credential format identifiers (OpenID4VCI 1.0 Appendix A) and their labels.
  const FORMATS = { SDJWT: 'dc+sd-jwt', MDOC: 'mso_mdoc', JWTVC: 'jwt_vc_json' };
  const FORMAT_LABELS = {
    [FORMATS.SDJWT]: { short: 'SD-JWT', long: 'SD-JWT VC' },
    [FORMATS.MDOC]: { short: 'mdoc', long: 'mdoc' },
    [FORMATS.JWTVC]: { short: 'JWT VC', long: 'JWT VC' },
  };
  const formatOptions = (formats) => formats.map(f => '<option value="' + f + '">' + FORMAT_LABELS[f].long + '</option>').join('');
  // The API answers errors with error and error_description (RFC 6749 §5.2).
  const apiErrorText = (result, resp) => (result && (result.error_description || result.error)) || ('HTTP ' + resp.status);

  // CSS chooses the menu layout. JavaScript only controls whether it is open.
  const menuToggle = document.getElementById('header-menu-toggle');
  const headerLinks = document.getElementById('header-links');
  if (menuToggle && headerLinks) {
    menuToggle.addEventListener('click', () => {
      const open = headerLinks.classList.toggle('open');
      menuToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    headerLinks.addEventListener('click', (e) => {
      if (e.target.tagName === 'A') {
        headerLinks.classList.remove('open');
        menuToggle.setAttribute('aria-expanded', 'false');
      }
    });
  }
  // A submenu opens on its entry and closes on a choice, Escape or a click
  // elsewhere.
  document.querySelectorAll('.header-submenu-toggle').forEach(toggle => {
    const submenu = document.getElementById(toggle.getAttribute('aria-controls'));
    const setOpen = open => {
      submenu.hidden = !open;
      toggle.setAttribute('aria-expanded', String(open));
    };
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      setOpen(submenu.hidden);
    });
    submenu.addEventListener('click', (e) => { if (e.target.tagName === 'A') setOpen(false); });
    document.addEventListener('click', (e) => { if (!submenu.hidden && !submenu.contains(e.target)) setOpen(false); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !submenu.hidden) { setOpen(false); toggle.focus(); } });
    toggle.parentElement.addEventListener('focusout', (e) => {
      if (!submenu.hidden && !toggle.parentElement.contains(e.relatedTarget)) setOpen(false);
    });
  });

  const pageParams = new URLSearchParams(window.location.search);
  // Keep the consent owner in sessionStorage for reloads and remove it from shareable
  // URLs.
  const actingOwner = readActingOwner();
  // The tab id names this page load. The wallet sends an issuer sign-in to one
  // page only, because the issuer accepts each authorization request once.
  // Unlike randomUUID, getRandomValues also works on plain http.
  const tabID = Array.from(crypto.getRandomValues(new Uint8Array(16)),
    (b) => b.toString(16).padStart(2, '0')).join('');
  const tabHeaders = { 'X-Eudi-Tab': tabID };
  // Read the request ID before clearing the address bar.
  const openedForRequest = pageParams.get('request') || '';

  // The request ID lets a browser without cookies answer its consent request.
  // docsURL links a page of the docs. A release links the docs of its own
  // tag. A beta's docs aren't on main yet. Other builds, such as a local
  // v3.1.2+dirty or a pseudo-version, have no tag and link main.
  function docsURL(doc) {
    const version = window.EUDI_VERSION || '';
    const ref = /^v\d+\.\d+\.\d+(-(beta|rc)\.\d+)?$/.test(version) ? version : 'main';
    return 'https://github.com/eudi-dev/eudi-dev/blob/' + encodeURIComponent(ref) + '/' + doc;
  }

  function approveURL(id, action) {
    const named = id === openedForRequest ? '?request=' + encodeURIComponent(id) : '';
    return 'api/requests/' + id + action + named;
  }

  function readActingOwner() {
    const named = pageParams.get('owner') || '';
    try {
      if (named) sessionStorage.setItem('eudi_owner', named);
      return named || sessionStorage.getItem('eudi_owner') || '';
    } catch (e) {
      return named;
    }
  }

  // Paths are relative to the wallet root. The server adds <base href> when the wallet
  // runs under a path prefix.
  const appBase = new URL('.', document.baseURI);

  // The main area reserves a scrollbar gutter whose width depends on the browser and OS.
  // The activity drawer below it takes the same right margin so both line up.
  const mainArea = document.querySelector('.main');
  if (mainArea) {
    const gutter = mainArea.offsetWidth - mainArea.clientWidth;
    document.documentElement.style.setProperty('--main-gutter', gutter + 'px');
  }

  const CLIENT_NAME = 'eudi-ui';
  const CLIENT_HEADER = 'X-Eudi-Client';
  const OWNER_HEADER = 'X-Eudi-Owner';
  (function nameThisClient() {
    const original = window.fetch;
    window.fetch = function (input, init) {
      const raw = typeof input === 'string' ? input : String((input && (input.url || input.href)) || '');
      // Add the client header to all wallet API calls, including absolute URLs and Request
      // objects.
      const target = new URL(raw, document.baseURI);
      if (target.origin !== window.location.origin || !target.pathname.startsWith(appBase.pathname + 'api/')) {
        return original(input, init);
      }
      const opts = Object.assign({}, init);
      const headers = new Headers(opts.headers || (typeof input === 'object' ? input.headers : undefined));
      headers.set(CLIENT_HEADER, CLIENT_NAME + '/' + (window.EUDI_VERSION || 'dev'));
      if (actingOwner) headers.set(OWNER_HEADER, actingOwner);
      opts.headers = headers;
      return original(input, opts);
    };
  })();

  let credentials = [];
  const openDescriptions = new Set();
  // Paginate on the server because shared wallets can hold many credentials.
  const CREDENTIALS_PER_PAGE = 10;
  let credentialPage = 0;
  let credentialTotal = 0;
  let credentialsLoaded = false;
  let logLoaded = false;
  let credentialLoadId = 0;
  let logLoadId = 0;

  const credContainer = document.getElementById('credentials');
  const credEmpty = document.getElementById('cred-empty');
  const credLoading = document.getElementById('cred-loading');
  const credError = document.getElementById('cred-error');
  const logContainer = document.getElementById('log');
  const logEmpty = document.getElementById('log-empty');
  const logLoading = document.getElementById('log-loading');
  const logError = document.getElementById('log-error');
  const offerInput = document.getElementById('offer-input');
  const processBtn = document.getElementById('process-btn');
  const importBtn = document.getElementById('import-btn');
  const importOverlay = document.getElementById('import-overlay');
  const importCancel = document.getElementById('import-cancel');
  const importSubmit = document.getElementById('import-submit');
  const importTextarea = document.getElementById('import-textarea');
  const consentOverlay = document.getElementById('consent-overlay');
  // A button that starts a request is disabled while it runs and loses the
  // focus. The error dialog gives the focus back to it.
  let lastPageFocus = null;
  document.addEventListener('focusin', (event) => {
    if (!event.target.closest('.consent-overlay')) lastPageFocus = event.target;
  });
  const consentDialog = document.getElementById('consent-dialog');

  async function loadDeferred() {
    try {
      const resp = await fetch('api/deferred');
      const pending = await resp.json();
      const section = document.getElementById('deferred-section');
      const list = document.getElementById('deferred-list');
      if (!section || !list) return;
      if (!Array.isArray(pending) || pending.length === 0) {
        section.hidden = true;
        list.innerHTML = '';
        return;
      }
      section.hidden = false;
      list.innerHTML = pending.map(p => {
        const display = p.display || {};
        const typeLabel = p.vct || p.doctype || p.credential_configuration_id || p.format || 'Credential';
        const name = display.name || typeLabel;
        const formatLabel = formatLabelFor(p);
        const next = p.next_attempt_at ? new Date(p.next_attempt_at) : null;
        const when = next && !isNaN(next) ? next.toLocaleTimeString() : '';
        const prefix = 'deferred-' + domID(p.id);
        const logoImg = display.logo_uri
          ? '<img class="credential-logo" id="' + prefix + '-logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
          : '';
        const faceHtml = '<div class="card-face" id="' + prefix + '-face">' +
            '<span class="format-badge format-badge-face" id="' + prefix + '-face-format">' + formatLabel + '</span>' +
            logoImg +
            '<div class="face-name" id="' + prefix + '-face-name">' + escHtml(name) + '</div>' +
          '</div>';
        return '<div class="deferred-item" id="' + prefix + '" data-id="' + domID(p.id) + '">' +
          faceHtml +
          '<div class="deferred-body">' +
            '<div class="deferred-item-head">' +
              '<span class="format-badge format-badge-row" id="' + prefix + '-format">' + formatLabel + '</span>' +
              '<span class="deferred-name" id="' + prefix + '-name">' + escHtml(name) + '</span>' +
              '<span class="status-badge deferred-awaiting" id="' + prefix + '-status">Awaiting issuance</span>' +
            '</div>' +
            '<div class="deferred-meta deferred-status" id="' + prefix + '-progress">' +
              '<span class="deferred-spinner" aria-hidden="true"></span>' +
              'Checks every ' + escHtml(p.interval || '') +
              (when ? '. Next at ' + escHtml(when) : '') +
              (p.attempts ? ' (' + escHtml(p.attempts) + ' attempts)' : '') +
            '</div>' +
            (p.issuer ? '<div class="deferred-meta" id="' + prefix + '-issuer">' + escHtml(p.issuer) + '</div>' : '') +
            (p.last_error ? '<div class="deferred-meta deferred-error" id="' + prefix + '-error">' + escHtml(p.last_error) + '</div>' : '') +
            '<div class="deferred-actions">' +
              '<button class="btn btn-sm deferred-check" id="' + prefix + '-check" data-id="' + domID(p.id) + '">Check now</button>' +
              '<button class="btn btn-sm btn-danger deferred-abandon" id="' + prefix + '-abandon" data-id="' + domID(p.id) + '">Abandon</button>' +
            '</div>' +
          '</div>' +
        '</div>';
      }).join('');

      list.querySelectorAll('.deferred-item').forEach(item => {
        const p = pending.find(x => String(x.id) === item.dataset.id);
        if (p) applyCredentialDisplay(item, p.display);
      });

      list.querySelectorAll('.deferred-check').forEach(btn => {
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          btn.textContent = 'Checking…';
          try {
            const resp = await fetch('api/deferred/' + encodeURIComponent(btn.dataset.id) + '/collect', { method: 'POST' });
            const result = await resp.json();
            if (result.abandoned) {
              showErrorDialog('Deferred credential was not issued', result.reason || 'The issuer refused it.');
            }
            await loadDeferred();
            await loadCredentials();
            await loadLog();
          } catch (e) {
            console.error('Checking a deferred credential failed:', e);
            btn.disabled = false;
            btn.textContent = 'Check now';
          }
        });
      });
      list.querySelectorAll('.deferred-abandon').forEach(btn => {
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          try {
            await fetch('api/deferred/' + encodeURIComponent(btn.dataset.id), { method: 'DELETE' });
            await loadDeferred();
            await loadLog();
          } catch (e) {
            console.error('Abandoning a deferred credential failed:', e);
            btn.disabled = false;
          }
        });
      });
    } catch (e) {
      console.error('Loading deferred issuances failed:', e);
    }
  }

  async function loadCredentials() {
    const loadId = ++credentialLoadId;
    // A renewal replaces a credential under the same id.
    candidateDetails.clear();
    credLoading.hidden = credentialsLoaded;
    credError.hidden = true;
    try {
      const offset = credentialPage * CREDENTIALS_PER_PAGE;
      const resp = await fetch('api/credentials?limit=' + CREDENTIALS_PER_PAGE + '&offset=' + offset);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const loadedCredentials = await resp.json();
      if (loadId !== credentialLoadId) return;
      credentials = loadedCredentials;
      credentialTotal = parseInt(resp.headers.get('X-Total-Count') || '0', 10);
      // Deleting the last credential on a page can move the offset past the end of the
      // list.
      if (credentials.length === 0 && credentialPage > 0) {
        credentialPage = Math.max(0, Math.ceil(credentialTotal / CREDENTIALS_PER_PAGE) - 1);
        return loadCredentials();
      }
      renderCredentials();
      renderPager();
      credentialsLoaded = true;
      // Issuance can create trusted lists, so refresh their links too.
      loadTrustLists();
    } catch (e) {
      if (loadId === credentialLoadId) credError.hidden = false;
      console.error('Failed to load credentials:', e);
    } finally {
      if (loadId === credentialLoadId) credLoading.hidden = true;
    }
  }

  document.getElementById('cred-retry').addEventListener('click', loadCredentials);

  // Consent summaries contain only requested claims. Cache full credentials for Edit,
  // including failed reads to avoid repeated requests, until the list reloads.
  const candidateDetails = new Map();

  async function loadCandidateDetails(ids) {
    const missing = ids.filter(id => !candidateDetails.has(id));
    if (missing.length === 0) return false;
    await Promise.all(missing.map(async id => {
      try {
        const resp = await fetch('api/credentials/' + encodeURIComponent(id));
        candidateDetails.set(id, resp.ok ? await resp.json() : null);
      } catch (e) {
        console.error('Loading credential ' + id + ' failed:', e);
        candidateDetails.set(id, null);
      }
    }));
    return true;
  }

  function renderPager() {
    const pager = document.getElementById('cred-pager');
    const pages = Math.ceil(credentialTotal / CREDENTIALS_PER_PAGE);
    if (pages <= 1) {
      pager.hidden = true;
      return;
    }
    const first = credentialPage * CREDENTIALS_PER_PAGE + 1;
    const last = first + credentials.length - 1;
    document.getElementById('cred-range').textContent =
      first + '\u2013' + last + ' of ' + credentialTotal;
    document.getElementById('cred-prev').disabled = credentialPage === 0;
    document.getElementById('cred-next').disabled = credentialPage >= pages - 1;
    pager.hidden = false;
  }

  document.getElementById('cred-prev').addEventListener('click', () => {
    if (credentialPage === 0) return;
    credentialPage--;
    loadCredentials();
  });
  document.getElementById('cred-next').addEventListener('click', () => {
    if ((credentialPage + 1) * CREDENTIALS_PER_PAGE >= credentialTotal) return;
    credentialPage++;
    loadCredentials();
  });

  function relativeTime(value) {
    if (!value) return '';
    const then = new Date(value);
    if (isNaN(then.getTime())) return '';
    const secs = Math.floor((Date.now() - then.getTime()) / 1000);
    const mins = Math.floor(secs / 60);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + ' min ago';
    const hours = Math.floor(mins / 60);
    if (hours < 24) return hours + ' h ago';
    const days = Math.floor(hours / 24);
    if (days < 30) return days + ' d ago';
    const months = Math.floor(days / 30);
    if (months < 12) return months + ' mo ago';
    return Math.floor(months / 12) + ' y ago';
  }

  // The first 8 characters tell generated IDs apart. A name from a credentials
  // file stays whole. API and CLI lookups use the full ID.
  function shortCredentialId(id) {
    const s = String(id || '');
    return /^[0-9a-f][0-9a-f-]{15,}$/i.test(s) ? s.slice(0, 8) : s;
  }

  function credentialInitials(name) {
    const words = String(name || '').replace(/[()]/g, ' ').split(/\s+/).filter(w => /^[a-z0-9]/i.test(w));
    return words.slice(0, 3).map(w => w[0]).join('').toUpperCase();
  }

  const GENERIC_FACE_GLYPH = '<span class="face-generic"><svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><rect x="3" y="5" width="18" height="14" rx="2.2"/><circle cx="8" cy="11" r="2"/><path d="M13 10h5M13 13h4M6 15.6h6"/></svg></span>';

  // An SVG lock inherits the text color. The emoji retains its own color.
  const LOCK_SVG = '<svg class="pill-ico" viewBox="0 0 24 24" width="11" height="11" fill="currentColor" aria-hidden="true"><path d="M12 1a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V6a5 5 0 0 0-5-5zm3 8H9V6a3 3 0 0 1 6 0v3z"/></svg>';

  function formatLabelFor(cred) {
    return (FORMAT_LABELS[cred.format] || FORMAT_LABELS[FORMATS.MDOC]).short;
  }

  function credentialCardBody(cred, idPrefix) {
    const formatLabel = formatLabelFor(cred);
    const typeLabel = cred.vct || cred.doctype || cred.format;
    const isProtected = cred.protected === true;

    const dataset = {
      credentialId: cred.id,
      format: formatLabel === 'SD-JWT' ? 'sdjwt' : formatLabel === 'JWT VC' ? 'jwt' : 'mdoc',
      status: 'none',
    };
    if (isProtected) dataset.protected = 'true';
    if (cred.vct) dataset.vct = cred.vct;
    if (cred.doctype) dataset.doctype = cred.doctype;

    // Protected credentials cannot be deleted or revoked, so hide those actions.
    const protectedBadge = isProtected
      ? '<span class="status-badge status-protected" id="' + idPrefix + 'protected-' + domID(cred.id) + '"' +
        ' title="Baseline credential. Can\'t be deleted or revoked.">' + LOCK_SVG + 'Protected</span>'
      : '';

    const st = cred.status;
    let statusBadge;
    if (st && st.managed) {
      const state = statusListState(st.status, st.statusName);
      dataset.status = state.key;
      statusBadge = '<span class="status-badge ' + state.cls + '" id="' + idPrefix + 'status-' + domID(cred.id) + '" title="' + escHtml(st.statusName || '') + ' (' + escHtml(st.uri || '') + ', index ' + st.idx + ')">' + escHtml(state.label) + '</span>';
    } else if (st && st.uri) {
      dataset.status = 'external';
      statusBadge = '<span class="status-badge status-external ico-half" id="' + idPrefix + 'status-' + domID(cred.id) + '" title="External status list, not checked (' + escHtml(st.uri) + ', index ' + st.idx + ')">External list</span>';
    } else {
      statusBadge = '<span class="status-badge status-none ico-circle" id="' + idPrefix + 'status-' + domID(cred.id) + '" title="No status list. Can\'t be revoked.">No status</span>';
    }

    const expiry = validityInfo(cred.valid_from, cred.expires_at);
    let expiryBadge = '';
    if (expiry) {
      dataset.expiry = expiry.state;
      expiryBadge = '<span class="status-badge status-' + expiry.state + ' ico-clock" id="' + idPrefix + 'expiry-' + domID(cred.id) +
        '" title="' + escHtml(expiry.title) + '">' + escHtml(expiry.label) + '</span>';
    }

    // An embedded key verifies signature consistency. It does not establish issuer trust
    // (ADR 0009).
    let signatureBadge = '';
    const sig = cred.signature;
    if (sig && sig.algorithm) {
      if (sig.self_consistent) {
        signatureBadge = '<span class="status-badge status-active ico-check" id="' + idPrefix + 'signature-' + domID(cred.id) +
          '" title="Verified with the credential\'s own x5c or jwk (' + escHtml(sig.algorithm) + '). Issuer not checked.">Self-consistent</span>';
      } else {
        const kind = cred.issuer && cred.issuer.kind ? ' · ' + escHtml(cred.issuer.kind.toUpperCase()) : '';
        signatureBadge = '<span class="status-badge status-revoked ico-x" id="' + idPrefix + 'signature-' + domID(cred.id) +
          '" title="No key to verify the signature offline.">Not verified' + kind + '</span>';
      }
    }

    let keyBindingBadge = '';
    const binding = cred.holder_binding ||
      (cred.key_binding_not_held === true ? 'other_key' : '');
    if (binding === 'this_wallet') {
      dataset.keyBinding = 'this-wallet';
      keyBindingBadge = '<span class="status-badge status-active ico-check" id="' + idPrefix + 'key-binding-' + domID(cred.id) +
        '" title="This wallet holds the holder key.">Bound to this wallet</span>';
    } else if (binding === 'other_key') {
      dataset.keyBinding = 'not-held';
      keyBindingBadge = '<span class="status-badge status-unheld-key ico-warn" id="' + idPrefix + 'key-binding-' + domID(cred.id) +
        '" title="This wallet doesn\'t hold the holder key. Key binding fails.">Bound to another key</span>';
    } else if (binding === 'none') {
      dataset.keyBinding = 'none';
      keyBindingBadge = '<span class="status-badge status-none" id="' + idPrefix + 'key-binding-' + domID(cred.id) +
        '" title="No holder key in the credential.">No key binding</span>';
    }

    const display = cred.display || {};
    const cp = idPrefix + 'credential-' + domID(cred.id) + '-';
    const logoImg = display.logo_uri
      ? '<img class="credential-logo" id="' + cp + 'logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
      : '';
    const faceLabel = display.name ? escHtml(display.name) : escHtml(typeLabel);

    const faceHtml = '<div class="card-face" id="' + cp + 'face">' +
      '<span class="format-badge format-badge-face" id="' + cp + 'face-format">' + formatLabel + '</span>' +
      logoImg +
      '<div class="face-name" id="' + cp + 'face-name">' + faceLabel + '</div>' +
      '</div>';

    const nameHtml = '<span class="credential-name" id="' + cp + 'name">' + faceLabel + '</span>';


    const idMeta = '<span class="cred-meta-item cred-m-id"><span class="cred-meta-k" id="' + cp + 'meta-id-key">id</span> <span class="mono cred-shortid" id="' + cp + 'meta-id">#' + escHtml(shortCredentialId(cred.id)) + '</span></span>';

    const rel = relativeTime(cred.issued_at);
    const issuedMeta = rel ? '<span class="cred-meta-item cred-m-iat" id="' + cp + 'meta-iat"><span class="cred-meta-k" id="' + cp + 'meta-iat-key">iat</span> ' + escHtml(rel) + '</span>' : '';

    const typeMeta = display.name
      ? '<span class="cred-meta-item cred-m-type"><span class="cred-meta-k" id="' + cp + 'meta-type-key">type</span> <span class="mono" id="' + cp + 'meta-type">' + escHtml(typeLabel) + '</span></span>'
      : '';

    let issuerMeta = '';
    if (cred.issuer && cred.issuer.value) {
      issuerMeta = '<span class="cred-meta-item cred-m-iss"><span class="cred-meta-k" id="' + cp + 'meta-iss-key">' + escHtml(cred.issuer.kind || 'iss') +
        '</span> <span class="mono" id="' + cp + 'meta-iss">' + escHtml(cred.issuer.value) + '</span></span>';
    }

    const bodyHtml = '<div class="credential-info" id="' + cp + 'info">' +
        '<div class="credential-type cred-hdr">' +
          '<span class="format-badge format-badge-row" id="' + cp + 'format">' + formatLabel + '</span>' +
          nameHtml +
        '</div>' +
        '<div class="cred-pills">' + protectedBadge + statusBadge + expiryBadge + signatureBadge + keyBindingBadge + '</div>' +
        '<div class="cred-meta">' +
          idMeta + issuedMeta + typeMeta + issuerMeta +
        '</div>' +
      '</div>';

    return { html: faceHtml + bodyHtml, dataset: dataset };
  }

  // Apply issuer display metadata from OID4VCI 1.0 §12.2.4 as style properties, with
  // validated values.
  function applyCredentialDisplay(card, display) {
    const face = card.querySelector('.card-face');
    if (!face) return;
    display = display || {};
    const textColor = String(display.text_color || '');
    const darkText = textColor.toLowerCase() === '#000' || textColor.toLowerCase() === '#000000';

    if (display.background_uri) {
      const scrim = darkText
        ? 'linear-gradient(0deg,rgba(255,255,255,.80),rgba(255,255,255,.12) 58%)'
        : 'linear-gradient(0deg,rgba(0,0,0,.62),rgba(0,0,0,.05) 58%)';
      // Keep the declared color beneath the image so it shows through transparent pixels.
      face.style.backgroundImage = scrim + ', url("' + display.background_uri.replace(/["\\]/g, '') + '")';
      if (display.background_color) face.style.backgroundColor = display.background_color;
      face.style.color = textColor || '#fff';
    } else if (display.background_color) {
      face.style.background = 'linear-gradient(135deg, ' + display.background_color +
        ', color-mix(in srgb, ' + display.background_color + ' 56%, #000))';
      face.style.color = textColor || '#fff';
    } else {
      face.classList.add('plain');
      if (!face.querySelector('.credential-logo')) {
        const name = display.name || '';
        const initials = credentialInitials(name);
        const nameEl = face.querySelector('.face-name');
        if (nameEl) {
          nameEl.insertAdjacentHTML('beforebegin', name && initials
            ? '<span class="face-init">' + escHtml(initials) + '</span>'
            : GENERIC_FACE_GLYPH);
          nameEl.previousElementSibling.id = card.id + (name && initials ? '-face-initials' : '-face-glyph');
        }
      }
    }

    const fb = face.querySelector('.format-badge-face');
    if (fb) {
      fb.style.color = textColor || '#fff';
      fb.style.background = darkText ? 'rgba(255,255,255,.62)' : 'rgba(0,0,0,.5)';
    }
  }

  function renderCredentials() {
    if (credentials.length === 0) {
      credEmpty.hidden = false;
      credContainer.querySelectorAll('.credential-card').forEach(el => el.remove());
      return;
    }
    credEmpty.hidden = true;
    credContainer.querySelectorAll('.credential-card').forEach(el => el.remove());

    credentials.forEach(cred => {
      const card = document.createElement('div');
      card.className = 'credential-card';
      if (openDescriptions.has(cred.id)) card.classList.add('desc-open');
      if (cred.batch) card.classList.add('batch');

      const isProtected = cred.protected === true;
      const body = credentialCardBody(cred, '');
      card.id = 'credential-' + domID(cred.id);
      Object.assign(card.dataset, body.dataset);

      const st = cred.status;
      let revokeBtn = '';
      if (st && st.managed) {
        if (!isProtected) {
          revokeBtn = '<button class="btn btn-sm" id="revoke-' + domID(cred.id) + '" data-revoke="' + escHtml(cred.id) + '">' + (st.status === 0 ? 'Revoke' : 'Activate') + '</button>';
        }
      } else if (st && st.uri) {
        revokeBtn = '<button class="btn btn-sm" id="status-check-' + domID(cred.id) + '" data-check-status="' + escHtml(cred.id) + '">Check status</button>';
      }

      // Container queries choose whether the description flips the card or expands beneath
      // it.
      const hasDesc = !!(cred.display && cred.display.description);
      const aboutBtn = hasDesc
        ? '<button class="btn btn-sm about-btn" id="about-' + domID(cred.id) + '" data-about="' + escHtml(cred.id) + '" aria-expanded="false">' +
            descIcon('ic-info', '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 7.6h.01"/>') +
            '<span id="about-' + domID(cred.id) + '-label">About</span>' +
            descIcon('ic-chev', '<path d="M6 9l6 6 6-6"/>') +
          '</button>'
        : '';
      const actionsHtml = '<div class="credential-actions">' +
          aboutBtn +
          revokeBtn +
          '<button class="btn btn-sm" id="show-' + domID(cred.id) + '" data-show="' + escHtml(cred.id) + '">Show</button>' +
          (isProtected ? '' : '<button class="btn btn-danger btn-sm" id="delete-' + domID(cred.id) + '" data-delete="' + escHtml(cred.id) + '">Delete</button>') +
        '</div>';
      // The flipped card hides the About button, so phones need a Back control inside the
      // description.
      const descPane = hasDesc
        ? '<div class="cred-desc" id="' + card.id + '-desc"><div class="cred-desc-in">' +
            '<div class="cred-desc-head"><span class="cred-desc-label" id="' + card.id + '-desc-label">Description</span>' +
              '<button class="cred-desc-back" id="' + card.id + '-desc-back" data-desc-close="' + escHtml(cred.id) + '">' +
                descIcon('', '<path d="M15 18l-6-6 6-6"/>') + '<span id="' + card.id + '-desc-back-label">Back</span></button></div>' +
            '<div class="cred-desc-body" id="' + card.id + '-desc-body">' + linkifyText(cred.display.description, card.id + '-desc-body') + '</div>' +
          '</div></div>'
        : '';
      card.innerHTML = '<div class="cred-front">' + body.html + actionsHtml + '</div>' + descPane;
      card.querySelector('.credential-info').title = 'Open in decoder';
      applyCredentialDisplay(card, cred.display);

      const openDecoder = () => {
        // The mounted decoder can look up credentials by ID, keeping links short.
        window.open('decoder/?id=' + encodeURIComponent(cred.id), '_blank');
      };
      card.querySelector('[data-show]').addEventListener('click', openDecoder);
      card.querySelector('.credential-info').addEventListener('click', openDecoder);
      card.querySelector('.card-face').addEventListener('click', openDecoder);
      const del = card.querySelector('[data-delete]');
      if (del) {
        del.addEventListener('click', () => deleteCredential(cred.id));
      }
      const revoke = card.querySelector('[data-revoke]');
      if (revoke) {
        revoke.addEventListener('click', () => setCredentialStatus(cred.id, st.status === 0 ? 1 : 0));
      }
      const check = card.querySelector('[data-check-status]');
      if (check) {
        check.addEventListener('click', () => checkCredentialStatus(cred.id));
      }

      const about = card.querySelector('[data-about]');
      if (about) {
        about.setAttribute('aria-expanded', String(openDescriptions.has(cred.id)));
        about.addEventListener('click', (e) => {
          e.stopPropagation();
          const open = card.classList.toggle('desc-open');
          if (open) openDescriptions.add(cred.id);
          else openDescriptions.delete(cred.id);
          about.setAttribute('aria-expanded', String(open));
        });
        const back = card.querySelector('[data-desc-close]');
        if (back) {
          back.addEventListener('click', (e) => {
            e.stopPropagation();
            card.classList.remove('desc-open');
            openDescriptions.delete(cred.id);
            about.setAttribute('aria-expanded', 'false');
          });
        }
      }
      credContainer.appendChild(card);
    });
  }

  function descIcon(cls, body) {
    return '<svg class="ic ' + cls + '" viewBox="0 0 24 24" width="13" height="13" fill="none" ' +
      'stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      body + '</svg>';
  }

  function validityInfo(validFrom, value) {
    const from = new Date(validFrom || NaN);
    if (!isNaN(from.getTime()) && from.getTime() > Date.now()) {
      return { state: 'not-yet-valid', label: 'Not yet valid', title: 'Valid from ' + from.toLocaleString() };
    }
    if (!value) return null;
    const when = new Date(value);
    if (isNaN(when.getTime())) return null;

    const absolute = when.toLocaleString();
    const seconds = (when.getTime() - Date.now()) / 1000;
    if (seconds <= 0) {
      return { state: 'expired', label: 'Expired', title: 'Expired ' + absolute };
    }
    const state = seconds < 24 * 3600 ? 'expiring' : 'valid';
    return { state: state, label: 'Valid ' + humanizeDuration(seconds), title: 'Valid until ' + absolute };
  }

  function humanizeDuration(seconds) {
    const units = [
      [365 * 24 * 3600, 'year'],
      [30 * 24 * 3600, 'month'],
      [24 * 3600, 'day'],
      [3600, 'hour'],
      [60, 'minute'],
    ];
    for (const [size, name] of units) {
      if (seconds >= size) {
        const count = Math.floor(seconds / size);
        return 'for ' + count + ' ' + name + (count === 1 ? '' : 's');
      }
    }
    return 'for less than a minute';
  }

  async function setCredentialStatus(id, status) {
    try {
      const resp = await fetch('api/credentials/' + id + '/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: status })
      });
      if (!resp.ok) {
        const result = await resp.json().catch(() => ({}));
        showAPIError('Setting the status failed', result, resp);
        return;
      }
      await loadCredentials();
      await loadLog();
    } catch (e) {
      showErrorDialog('Setting the status failed', e.message);
    }
  }

  // Status Type values from draft-ietf-oauth-status-list §7.1. Any value other
  // than VALID makes the credential unusable.
  function statusListState(value, name) {
    switch (value) {
      case 0: return { key: 'active', label: 'Active', cls: 'status-active ico-dot' };
      case 1: return { key: 'revoked', label: 'Revoked', cls: 'status-revoked ico-block' };
      case 2: return { key: 'suspended', label: 'Suspended', cls: 'status-suspended ico-pause' };
      default: return { key: 'other', label: name || 'Status ' + value, cls: 'status-revoked ico-warn' };
    }
  }

  async function checkCredentialStatus(id) {
    const badge = document.getElementById('status-' + id);
    if (badge) badge.textContent = 'Checking…';
    try {
      const resp = await fetch('api/credentials/' + id + '/status');
      const result = await resp.json();
      if (!badge) return;
      if (!resp.ok) {
        badge.textContent = 'Check failed';
        badge.title = apiErrorText(result, resp);
        return;
      }
      const state = statusListState(result.status, result.statusName);
      badge.textContent = state.label;
      const notes = [].concat(result.warnings || [], result.haipFindings || []);
      if (!result.trustAnchored) notes.unshift('Not anchored in a trusted list');
      badge.title = [result.statusName + ' (' + result.uri + ', index ' + result.idx + ')',
        result.signatureInfo ? 'Status list ' + result.signatureInfo : ''].concat(notes).filter(Boolean).join('. ');
      badge.className = 'status-badge ' + state.cls;
      const card = document.getElementById('credential-' + id);
      if (card) card.dataset.status = state.key;
    } catch (e) {
      if (badge) {
        badge.textContent = 'Check failed';
        badge.title = e.message;
      }
    }
  }

  async function deleteCredential(id) {
    try {
      const resp = await fetch('api/credentials/' + id, { method: 'DELETE' });
      if (!resp.ok) {
        showAPIError('Deleting the credential failed', await resp.json().catch(() => ({})), resp);
        return;
      }
      openDescriptions.delete(id);
      await loadCredentials();
      await loadLog();
    } catch (e) {
      showErrorDialog('Deleting the credential failed', e.message);
    }
  }

  processBtn.addEventListener('click', async () => {
    const uri = offerInput.value.trim();
    if (!uri) return;

    processBtn.disabled = true;
    processBtn.textContent = 'Processing…';

    try {
      const isVCI = uri.includes('credential_offer') ||
        uri.startsWith('openid-credential-offer://') ||
        uri.startsWith('haip-vci://') ||
        uri.startsWith('eu-eaa-offer://');
      const endpoint = isVCI ? 'api/offers' : 'api/presentations';
      expectError();

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...tabHeaders },
        body: JSON.stringify({ uri: uri, interactive: true })
      });

      const result = await resp.json();
      if (followVerifierRedirect(result)) return;
      if (result.error) {
        await showFlowError(isVCI ? 'The wallet refused the credential offer' : 'The wallet refused the request', result, resp);
      } else {
        offerInput.value = '';
        await loadCredentials();
        await loadLog();
      }
    } catch (e) {
      // The flow goes on in the wallet. Its consent dialog stays open.
      if (!consentRequestOpen) showErrorDialog('The request failed', e.message);
    } finally {
      processBtn.disabled = false;
      processBtn.textContent = 'Process';
    }
  });

  const importError = document.getElementById('import-error');

  importBtn.addEventListener('click', () => {
    importOverlay.classList.add('active');
    importTextarea.value = '';
    importError.textContent = '';
    importTextarea.focus();
  });

  importCancel.addEventListener('click', () => {
    importOverlay.classList.remove('active');
  });

  importSubmit.addEventListener('click', async () => {
    const raw = importTextarea.value.trim();
    if (!raw) return;

    try {
      const resp = await fetch('api/credentials', {
        method: 'POST',
        body: raw
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        importError.textContent = 'Import failed: ' + apiErrorText(err, resp);
        return;
      }
      importOverlay.classList.remove('active');
      await loadCredentials();
    } catch (e) {
      importError.textContent = 'Import failed: ' + e.message;
    }
  });

  const issueBtn = document.getElementById('issue-btn');
  const issueOverlay = document.getElementById('issue-overlay');
  const issueForm = document.getElementById('issue-form');
  const issueError = document.getElementById('issue-error');
  const issueSubmit = document.getElementById('issue-submit');
  const issueFormat = document.getElementById('issue-format');
  const issueClaimRows = document.getElementById('issue-claim-rows');
  const issueClaimsTextarea = document.getElementById('issue-claims');
  const issueTemplateSelect = document.getElementById('issue-template');
  const issueAlwaysDisclosed = document.getElementById('issue-always-disclosed');
  let claimRowCounter = 0;
  let templatesCache = null;

  function addClaimRow(ns, key, value, sd) {
    const idx = claimRowCounter++;
    const row = document.createElement('div');
    row.className = 'claim-row';
    row.id = 'issue-claim-row-' + idx;
    row.innerHTML =
      '<input type="text" class="form-input claim-ns" id="issue-claim-ns-' + idx + '" placeholder="namespace (default: doc type)">' +
      '<input type="text" class="form-input" id="issue-claim-key-' + idx + '" placeholder="claim name">' +
      '<input type="text" class="form-input" id="issue-claim-value-' + idx + '" placeholder="value (text or JSON)">' +
      '<label class="claim-sd" id="issue-claim-sd-label-' + idx + '" title="Allow selective disclosure. Uncheck to always disclose this claim."><input type="checkbox" id="issue-claim-sd-' + idx + '" checked> SD</label>' +
      '<button type="button" class="btn btn-sm" id="issue-claim-remove-' + idx + '" title="Remove claim">&times;</button>';
    row.querySelector('input[id^="issue-claim-ns-"]').value = ns || '';
    row.querySelector('input[id^="issue-claim-key-"]').value = key || '';
    row.querySelector('input[id^="issue-claim-value-"]').value = value || '';
    row.querySelector('input[id^="issue-claim-sd-"]').checked = sd !== false;
    row.querySelector('input[id^="issue-claim-sd-"]').addEventListener('change', syncAlwaysDisclosedFromRows);
    row.querySelector('button').addEventListener('click', () => row.remove());
    issueClaimRows.appendChild(row);
  }

  function alwaysDisclosedList() {
    return issueAlwaysDisclosed.value.split(',').map(s => s.trim()).filter(Boolean);
  }

  // The Always visible input stores all paths. Row checkboxes represent only its top level
  // claims.
  function alwaysDisclosedFromRows() {
    const nested = alwaysDisclosedList().filter(p => p.indexOf('.') !== -1);
    const plain = [];
    issueClaimRows.querySelectorAll('.claim-row').forEach(row => {
      const key = row.querySelector('input[id^="issue-claim-key-"]').value.trim();
      const sd = row.querySelector('input[id^="issue-claim-sd-"]').checked;
      if (key && !sd) plain.push(key);
    });
    return plain.concat(nested);
  }

  function syncAlwaysDisclosedFromRows() {
    issueAlwaysDisclosed.value = alwaysDisclosedFromRows().join(', ');
  }

  function syncRowsFromAlwaysDisclosed() {
    const list = alwaysDisclosedList();
    issueClaimRows.querySelectorAll('.claim-row').forEach(row => {
      const key = row.querySelector('input[id^="issue-claim-key-"]').value.trim();
      row.querySelector('input[id^="issue-claim-sd-"]').checked = list.indexOf(key) === -1;
    });
  }

  // mdoc claim keys use namespace:element, matching the server format.
  function builderClaims() {
    const claims = {};
    issueClaimRows.querySelectorAll('.claim-row').forEach(row => {
      let key = row.querySelector('input[id^="issue-claim-key-"]').value.trim();
      if (!key) return;
      const ns = row.querySelector('input[id^="issue-claim-ns-"]').value.trim();
      if (ns && issueFormat.value === 'mdoc') key = ns + ':' + key;
      const rawVal = row.querySelector('input[id^="issue-claim-value-"]').value;
      let val = rawVal;
      try { val = JSON.parse(rawVal); } catch (e) { /* Leave non-JSON input as a string. */ }
      claims[key] = val;
    });
    return claims;
  }

  function fillClaimRows(claims) {
    issueClaimRows.textContent = '';
    claimRowCounter = 0;
    Object.keys(claims || {}).forEach(key => {
      const val = claims[key];
      let ns = '';
      let name = key;
      if (issueFormat.value === 'mdoc') {
        const sep = key.indexOf(':');
        if (sep > 0) {
          ns = key.slice(0, sep);
          name = key.slice(sep + 1);
        }
      }
      addClaimRow(ns, name, typeof val === 'string' ? val : JSON.stringify(val));
    });
    if (claimRowCounter === 0) addClaimRow('', '', '');
  }

  function updateIssueFormatFields() {
    const fmt = issueFormat.value;
    issueForm.querySelectorAll('[data-formats]').forEach(el => {
      el.hidden = el.dataset.formats.split(' ').indexOf(fmt) === -1;
    });
    issueClaimRows.classList.toggle('show-ns', fmt === 'mdoc');
    issueClaimRows.classList.toggle('show-sd', fmt === 'sdjwt');
    updateAlwaysDisclosedVisibility();
  }

  function updateAlwaysDisclosedVisibility() {
    const show = issueFormat.value === 'sdjwt' &&
      document.getElementById('issue-claims-mode-json').checked;
    issueAlwaysDisclosed.hidden = !show;
    issueForm.querySelector('label[for="issue-always-disclosed"]').hidden = !show;
  }

  // Saving under the name of another template replaces it.
  async function confirmTemplateName(name, current) {
    if (name === current) return true;
    let templates = [];
    try {
      templates = await loadTemplates(true);
    } catch (e) {
      return true;
    }
    if (!templates.some((tpl) => tpl.name === name)) return true;
    return window.confirm('Replace the template "' + name + '"?');
  }

  async function loadTemplates(force) {
    if (templatesCache && !force) return templatesCache;
    const resp = await fetch('api/templates');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    templatesCache = await resp.json();
    return templatesCache;
  }

  async function fillIssueTemplateSelect() {
    let templates = [];
    try {
      templates = await loadTemplates(true);
    } catch (e) {
      return;
    }
    const current = issueTemplateSelect.value;
    issueTemplateSelect.textContent = '';
    const none = document.createElement('option');
    none.value = '';
    none.textContent = '(none)';
    issueTemplateSelect.appendChild(none);
    templates.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t.name;
      opt.textContent = t.name + (t.predefined ? ' (predefined)' : '');
      issueTemplateSelect.appendChild(opt);
    });
    issueTemplateSelect.value = current || '';
  }

  // Send the template name so the server applies the template's images.
  let issueDisplayTemplate = '';
  // issueTemplateDisplay is the display of that template. issueTemplateImages names the
  // template images the card keeps. The form shows them as previews and keeps its own
  // fields for replacements.
  let issueTemplateDisplay = {};
  let issueTemplateImages = {};

  const ISSUE_IMAGE_FIELDS = [
    { input: 'issue-logo', preview: 'issue-logo-preview', remove: 'issue-logo-remove', key: 'logo' },
    { input: 'issue-bg-image', preview: 'issue-bg-image-preview', remove: 'issue-bg-image-remove', key: 'background_image' },
  ];

  // updateIssueImagePreviews shows each field's image, or the template's own image
  // while the field is empty.
  function updateIssueImagePreviews() {
    for (const f of ISSUE_IMAGE_FIELDS) {
      const input = document.getElementById(f.input);
      const preview = document.getElementById(f.preview);
      if (!input.dataset.placeholder) input.dataset.placeholder = input.placeholder;
      const value = input.value.trim();
      let src = '';
      if (value.startsWith('data:image/')) {
        src = value;
      } else if (!value && issueTemplateImages[f.key]) {
        src = 'api/templates/' + encodeURIComponent(issueDisplayTemplate) + '/display/' + f.key;
      }
      input.placeholder = !value && issueTemplateImages[f.key]
        ? 'The template\'s image. Upload a file, or paste a data URI or https link to replace it'
        : input.dataset.placeholder;
      preview.parentElement.hidden = !src;
      preview.hidden = false;
      if (src) preview.src = src; else preview.removeAttribute('src');
    }
  }
  for (const f of ISSUE_IMAGE_FIELDS) {
    document.getElementById(f.input).addEventListener('input', updateIssueImagePreviews);
    // A linked template image has no copy to preview. The × stays, so it can be removed.
    document.getElementById(f.preview).addEventListener('error', (e) => { e.target.hidden = true; });
    // The button removes the image the preview shows: the field's own image first,
    // then the template's.
    document.getElementById(f.remove).addEventListener('click', () => {
      const input = document.getElementById(f.input);
      if (input.value.trim()) input.value = '';
      else issueTemplateImages[f.key] = false;
      updateIssueImagePreviews();
    });
  }

  // Clear fields omitted by a new template to prevent values from mixing. Explicit form
  // values preserve user edits.
  function applyIssueTemplate(name) {
    const tpl = (templatesCache || []).find(t => t.name === name);
    if (tpl) applyTemplateToForm(tpl);
  }

  function applyTemplateToForm(tpl) {
    const display = tpl.display || {};
    issueDisplayTemplate = (display.logo || display.background_image) ? tpl.name : '';
    issueTemplateDisplay = display;
    issueTemplateImages = { logo: !!display.logo, background_image: !!display.background_image };
    if (tpl.format) issueFormat.value = tpl.format;
    updateIssueFormatFields();
    document.getElementById('issue-vct').value = tpl.vct || '';
    document.getElementById('issue-doctype').value = tpl.doctype || '';
    document.getElementById('issue-exp').value = tpl.exp || '';
    document.getElementById('issue-nbf').value = '';
    issueAlwaysDisclosed.value = (tpl.always_disclosed || []).join(', ');
    fillClaimRows(tpl.claims || {});
    syncRowsFromAlwaysDisclosed();
    issueClaimsTextarea.value = JSON.stringify(tpl.claims || {}, null, 2);
    applyTemplateDisplay(tpl.display || {});
  }

  // Keep template images when the user edits other display fields.
  function applyTemplateDisplay(display) {
    document.getElementById('issue-display-name').value = display.name || '';
    document.getElementById('issue-display-description').value = display.description || '';
    const bg = document.getElementById('issue-bg-color');
    bg.value = display.background_color || '';
    bg.dispatchEvent(new Event('input'));
    const text = document.getElementById('issue-text-color');
    text.value = display.text_color || '';
    text.dispatchEvent(new Event('input'));
    document.getElementById('issue-logo').value = '';
    document.getElementById('issue-logo-alt').value = '';
    document.getElementById('issue-bg-image').value = '';
    updateIssueImagePreviews();
  }

  function updateClaimsMode() {
    const jsonRadio = document.getElementById('issue-claims-mode-json');
    const jsonMode = jsonRadio.checked;
    if (jsonMode) {
      syncAlwaysDisclosedFromRows();
      issueClaimsTextarea.value = JSON.stringify(builderClaims(), null, 2);
    } else {
      const text = issueClaimsTextarea.value.trim();
      if (text) {
        try {
          const parsed = JSON.parse(text);
          if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            throw new Error('expected a JSON object');
          }
          fillClaimRows(parsed);
          syncRowsFromAlwaysDisclosed();
          issueError.textContent = '';
        } catch (e) {
          issueError.textContent = 'Claims must be valid JSON: ' + e.message;
          jsonRadio.checked = true;
          return;
        }
      }
    }
    issueClaimRows.hidden = jsonMode;
    document.getElementById('issue-add-claim').hidden = jsonMode;
    issueClaimsTextarea.hidden = !jsonMode;
    updateAlwaysDisclosedVisibility();
  }

  // catalogSchema reads the TS11 SchemaMeta fields of a form whose inputs are
  // named <prefix>-catalog-rulebook, -los, -binding and -trust.
  function catalogSchema(prefix) {
    const field = (name) => document.getElementById(prefix + '-catalog-' + name);
    const trust = field('trust').value.trim();
    return {
      rulebookURI: field('rulebook').value.trim(),
      attestationLoS: field('los').value,
      bindingType: field('binding').value,
      trustedAuthorities: trust ? [{ frameworkType: 'etsi_tl', value: trust, isLOTE: true }] : [],
    };
  }

  // The credential categories come from the registrar (GET
  // api/catalog/categories). A category sets the default level of security.
  let categories = [];
  const categoryOf = (id) => categories.find(c => c.id === id) || categories[categories.length - 1] || {};
  const categoryLevel = (id) => categoryOf(id).attestationLoS || (schemaOptions.attestationLoS[0] || {}).value || '';
  // The levels of security and holder bindings of a catalogue entry come
  // from the registrar (GET api/catalog/schema-options).
  let schemaOptions = { attestationLoS: [], bindingType: [] };
  const optionLabel = (field, value) => (schemaOptions[field].find(o => o.value === value) || {}).label || value;
  const defaultBinding = () => (schemaOptions.bindingType[0] || {}).value || '';
  async function loadSchemaOptions() {
    schemaOptions = await registrarRequest('GET', 'api/catalog/schema-options');
    const fill = (id, options, label) => {
      const select = document.getElementById(id);
      if (!select) return;
      const current = select.value || select.dataset.wanted || '';
      select.querySelectorAll('option[data-schema-option]').forEach(o => o.remove());
      options.forEach(o => {
        const option = document.createElement('option');
        option.value = o.value;
        option.textContent = label(o);
        option.dataset.schemaOption = '';
        select.appendChild(option);
      });
      if (current) select.value = current;
    };
    ['registrar', 'issue'].forEach(prefix => {
      fill(prefix + '-catalog-los', schemaOptions.attestationLoS, o => o.label);
      fill(prefix + '-catalog-binding', schemaOptions.bindingType, o => o.label);
    });
    // Appendix D.2 of OpenID4VCI 1.0 uses the same ISO/IEC 18045 values.
    fill('conf-key-attestation-select', schemaOptions.attestationLoS.slice().reverse(), o => o.label + ' (' + o.value + ')');
  }
  loadSchemaOptions().catch(() => { /* The selects keep their fixed options. */ });
  const categoryLabel = (id) => (categories.find(c => c.id === id) || {}).label || id;
  async function loadCategories() {
    categories = await registrarRequest('GET', 'api/catalog/categories');
    const entitlement = document.getElementById('registrar-entitlement');
    if (entitlement) {
      entitlement.innerHTML = '<option value="">From the attestation types</option>' +
        categories.map(c => '<option value="' + escHtml(c.entitlement) + '">' + escHtml(c.label) + ' provider</option>').join('');
    }
    ['registrar-catalog-category', 'issue-catalog-category'].forEach(selectID => {
      const select = document.getElementById(selectID);
      if (!select) return;
      const current = select.value || 'eaa';
      select.innerHTML = categories.map(c => '<option value="' + escHtml(c.id) + '">' + escHtml(c.description) + '</option>').join('');
      select.value = current;
    });
  }
  loadCategories().catch(() => { /* The category selects stay empty. */ });
  function linkCategoryLevel(prefix) {
    const category = document.getElementById(prefix + '-catalog-category');
    category.addEventListener('change', () => {
      document.getElementById(prefix + '-catalog-los').value = categoryLevel(category.value);
    });
  }
  // The trusted list field stays empty when the entry uses its category's
  // list, so the list follows the category.
  const ownCategoryList = (trust, category) => trust && trust.value.endsWith('trustlists/' + category);

  // catalogFields drives the "Add the template to the attestation catalogue"
  // checkbox and its fields in a form. entry() returns the catalogue fields
  // for the save request, or null when the box is unchecked.
  function catalogFields(prefix) {
    const box = document.getElementById(prefix + '-catalog');
    const fields = document.getElementById(prefix + '-catalog-fields');
    const field = (name) => document.getElementById(prefix + '-catalog-' + name);
    box.addEventListener('change', () => { fields.hidden = !box.checked; });
    return {
      reset() {
        box.checked = false;
        fields.hidden = true;
        field('name').value = '';
        field('category').value = 'eaa';
        field('rulebook').value = '';
        field('los').value = categoryLevel('eaa');
        field('binding').value = defaultBinding();
        field('trust').value = '';
      },
      // validate returns the first problem found in the browser. The server
      // checks the rest and refuses the whole save.
      validate(defaultName) {
        if (!box.checked) return '';
        if (!field('name').value.trim() && !defaultName) return 'The catalogue needs a name for the attestation';
        for (const name of ['rulebook', 'trust']) {
          const value = field(name).value.trim();
          if (value && !/^https?:\/\/\S+$/i.test(value)) {
            return (name === 'rulebook' ? 'The rulebook' : 'The trusted list') + ' must be an http or https URL';
          }
        }
        return '';
      },
      fill(entry) {
        box.checked = true;
        fields.hidden = false;
        const schema = entry.schema || {};
        field('name').value = entry.name || '';
        field('category').value = entry.category || 'eaa';
        field('rulebook').value = schema.rulebookURI || '';
        field('los').value = schema.attestationLoS || categoryLevel(field('category').value);
        field('binding').value = schema.bindingType || 'key';
        const trust = (schema.trustedAuthorities || [])[0];
        field('trust').value = trust && !ownCategoryList(trust, entry.category) ? trust.value : '';
      },
      entry(defaultName) {
        if (!box.checked) return null;
        return { name: field('name').value.trim() || defaultName, category: field('category').value, schema: catalogSchema(prefix) };
      },
    };
  }
  const issueCatalog = catalogFields('issue');
  linkCategoryLevel('issue');
  // The catalogue takes a template, so issuing offers it only with a
  // template name. The template editor always offers it.
  function syncIssueCatalog() {
    const show = issueForm.classList.contains('template-mode') ||
      document.getElementById('issue-save-template').value.trim() !== '';
    document.querySelectorAll('.issue-catalog-part').forEach((el) => { el.hidden = !show; });
    if (!show) issueCatalog.reset();
  }
  document.getElementById('issue-save-template').addEventListener('input', syncIssueCatalog);

  // Reset other fields when the format changes because their values may not apply.
  function resetIssueFields() {
    document.getElementById('issue-vct').value = '';
    document.getElementById('issue-doctype').value = '';
    document.getElementById('issue-exp').value = '';
    document.getElementById('issue-nbf').value = '';
    document.getElementById('issue-batch').value = '';
    document.getElementById('issue-binding').value = 'bound';
    document.getElementById('issue-save-template').value = '';
    issueCatalog.reset();
    syncIssueCatalog();
    document.getElementById('issue-status-list').value = 'auto';
    document.getElementById('issue-status-list-uri').value = '';
    document.getElementById('issue-status-list-uri').hidden = true;
    document.getElementById('issue-status-list-idx').value = '';
    document.getElementById('issue-status-list-idx').hidden = true;
    issueTemplateSelect.value = '';
    issueAlwaysDisclosed.value = '';
    issueDisplayTemplate = '';
    issueTemplateDisplay = {};
    issueTemplateImages = {};
    applyTemplateDisplay({});
    document.getElementById('issue-claims-mode-builder').checked = true;
    issueClaimsTextarea.value = '';
    issueError.textContent = '';
    updateIssueFormatFields();
    fillClaimRows({});
    updateClaimsMode();
  }

  // A wallet has a status list only when its serving configuration provides a URL.
  async function updateStatusListOption() {
    const autoOption = document.getElementById('issue-status-list-auto');
    try {
      const resp = await fetch('api/config');
      const config = await resp.json();
      const configured = Boolean(config.status_list_url);
      autoOption.disabled = !configured;
      autoOption.textContent = configured ? 'Wallet status list' : 'Wallet status list (not configured)';
      if (!configured && document.getElementById('issue-status-list').value === 'auto') {
        document.getElementById('issue-status-list').value = 'none';
      }
    } catch (e) {
      // Keep the default when configuration cannot be loaded.
    }
  }

  issueBtn.addEventListener('click', () => {
    setTemplateMode(null);
    issueForm.reset();
    resetIssueFields();
    issueOverlay.classList.add('active');
    fillIssueTemplateSelect();
    updateStatusListOption();
  });

  issueFormat.addEventListener('change', resetIssueFields);

  issueTemplateSelect.addEventListener('change', () => {
    if (issueTemplateSelect.value) {
      applyIssueTemplate(issueTemplateSelect.value);
    } else {
      const format = issueFormat.value;
      issueForm.reset();
      issueFormat.value = format;
      resetIssueFields();
    }
  });

  issueAlwaysDisclosed.addEventListener('change', syncRowsFromAlwaysDisclosed);

  document.getElementById('issue-status-list').addEventListener('change', () => {
    const custom = document.getElementById('issue-status-list').value === 'custom';
    document.getElementById('issue-status-list-uri').hidden = !custom;
    document.getElementById('issue-status-list-idx').hidden = !custom;
  });

  document.getElementById('issue-add-claim').addEventListener('click', () => addClaimRow('', ''));

  document.getElementById('issue-claims-mode-builder').addEventListener('change', updateClaimsMode);
  document.getElementById('issue-claims-mode-json').addEventListener('change', updateClaimsMode);

  document.getElementById('issue-cancel').addEventListener('click', () => {
    issueOverlay.classList.remove('active');
    if (templateEditor) {
      setTemplateMode(null);
      templatesOverlay.classList.add('active');
    }
  });

  function bindColorPicker(pickerId, textId) {
    const picker = document.getElementById(pickerId);
    const text = document.getElementById(textId);
    picker.addEventListener('input', () => { text.value = picker.value; });
    text.addEventListener('input', () => {
      if (/^#[0-9a-fA-F]{6}$/.test(text.value.trim())) picker.value = text.value.trim();
    });
  }
  bindColorPicker('issue-bg-color-picker', 'issue-bg-color');
  bindColorPicker('issue-text-color-picker', 'issue-text-color');

  // Both images travel base64-encoded in one request, which the wallet limits to 1 MB.
  const MAX_UPLOAD_BYTES = 350 * 1024;

  function bindImageUpload(fileId, textId) {
    document.getElementById(fileId).addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      if (file.size > MAX_UPLOAD_BYTES) {
        issueError.textContent = 'The image is too large. Choose one up to 350 KB.';
        e.target.value = '';
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        document.getElementById(textId).value = reader.result;
        updateIssueImagePreviews();
      };
      reader.onerror = () => { issueError.textContent = 'Could not read the selected file.'; };
      reader.readAsDataURL(file);
    });
  }
  bindImageUpload('issue-logo-file', 'issue-logo');
  bindImageUpload('issue-bg-image-file', 'issue-bg-image');

  // issueRequestBody is the body of POST api/issue for the form's values. It
  // throws an Error with a message for the form.
  function issueRequestBody() {
    const body = { format: issueFormat.value };
    if (document.getElementById('issue-claims-mode-json').checked) {
      const claimsText = issueClaimsTextarea.value.trim();
      if (claimsText) {
        try {
          body.claims = JSON.parse(claimsText);
        } catch (e) {
          throw new Error('Claims must be valid JSON: ' + e.message);
        }
      }
    } else {
      const claims = builderClaims();
      if (Object.keys(claims).length > 0) body.claims = claims;
    }
    const vct = document.getElementById('issue-vct').value.trim();
    if (vct) body.vct = vct;
    const doctype = document.getElementById('issue-doctype').value.trim();
    if (doctype) body.doctype = doctype;
    const exp = document.getElementById('issue-exp').value.trim();
    if (exp) body.exp = exp;
    const nbf = document.getElementById('issue-nbf').value.trim();
    if (nbf) body.nbf = nbf;
    // Each batch copy uses a distinct holder key. The wallet rotates between copies during
    // presentation. A JWT VC has no batch and no holder binding choice.
    if (issueFormat.value !== 'jwt') {
      const batch = parseInt(document.getElementById('issue-batch').value, 10);
      if (batch >= 2) body.batch = batch;
      if (document.getElementById('issue-binding').value === 'unbound') body.unbound = true;
    }
    const statusListMode = document.getElementById('issue-status-list').value;
    if (statusListMode === 'none') {
      body.status_list_uri = '';
    } else if (statusListMode === 'custom') {
      body.status_list_uri = document.getElementById('issue-status-list-uri').value.trim();
      const idx = document.getElementById('issue-status-list-idx').value.trim();
      if (idx) body.status_list_idx = parseInt(idx, 10);
    }
    if (issueFormat.value === 'sdjwt') {
      const always = document.getElementById('issue-claims-mode-json').checked ? alwaysDisclosedList() : alwaysDisclosedFromRows();
      if (always.length > 0) body.always_disclosed = always;
    }
    const saveTemplate = document.getElementById('issue-save-template').value.trim();
    if (saveTemplate) body.save_as_template = saveTemplate;
    const catalogProblem = issueCatalog.validate(saveTemplate);
    if (catalogProblem) throw new Error(catalogProblem);
    const catalog = issueCatalog.entry(saveTemplate);
    if (catalog && !saveTemplate) throw new Error('Enter a template name to add the template to the catalogue');
    if (catalog) body.catalog = catalog;
    const signingKey = document.getElementById('issue-signing-key').value.trim();
    if (signingKey) body.signing_key = signingKey;
    const signingCert = document.getElementById('issue-signing-cert').value.trim();
    if (signingCert) body.signing_cert = signingCert;

    const display = {};
    const dName = document.getElementById('issue-display-name').value.trim();
    if (dName) display.name = dName;
    const dDesc = document.getElementById('issue-display-description').value.trim();
    if (dDesc) display.description = dDesc;
    const bgColor = document.getElementById('issue-bg-color').value.trim();
    if (bgColor) display.background_color = bgColor;
    const txtColor = document.getElementById('issue-text-color').value.trim();
    if (txtColor) display.text_color = txtColor;
    const logo = document.getElementById('issue-logo').value.trim();
    if (logo) display.logo = logo;
    const logoAlt = document.getElementById('issue-logo-alt').value.trim();
    if (logoAlt) display.logo_alt_text = logoAlt;
    const bgImage = document.getElementById('issue-bg-image').value.trim();
    if (bgImage) display.background_image = bgImage;
    // The server applies template display values beneath fields explicitly supplied by the
    // form. Without a removed template image the template's name is enough. Otherwise the
    // display carries the template images the card keeps.
    const removed = ISSUE_IMAGE_FIELDS.some(f => issueTemplateDisplay[f.key] && !issueTemplateImages[f.key]);
    if (issueDisplayTemplate && !removed) {
      body.display_template = issueDisplayTemplate;
    } else if (issueDisplayTemplate) {
      if (issueTemplateImages.logo && !display.logo) {
        display.logo = issueTemplateDisplay.logo;
        if (!display.logo_alt_text && issueTemplateDisplay.logo_alt_text) display.logo_alt_text = issueTemplateDisplay.logo_alt_text;
      }
      if (issueTemplateImages.background_image && !display.background_image) display.background_image = issueTemplateDisplay.background_image;
    }
    if (Object.keys(display).length > 0) body.display = display;

    return body;
  }

  issueForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    issueError.textContent = '';
    if (templateEditor) {
      await saveTemplateFromEditor();
      return;
    }

    let body;
    try {
      body = issueRequestBody();
    } catch (e) {
      issueError.textContent = e.message;
      return;
    }
    if (body.save_as_template && !(await confirmTemplateName(body.save_as_template))) return;

    issueSubmit.disabled = true;
    issueSubmit.textContent = 'Issuing…';
    try {
      const resp = await fetch('api/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const result = await resp.json();
      if (!resp.ok) {
        issueError.textContent = apiErrorText(result, resp);
        return;
      }
      issueOverlay.classList.remove('active');
      if (body.save_as_template) templatesCache = null;
      await loadCredentials();
      await loadLog();
    } catch (e) {
      issueError.textContent = 'Request failed: ' + e.message;
    } finally {
      issueSubmit.disabled = false;
      issueSubmit.textContent = 'Issue';
    }
  });

  const templatesOverlay = document.getElementById('templates-overlay');
  const templatesList = document.getElementById('templates-list');
  const templateError = document.getElementById('template-error');
  const templateEditorHead = document.getElementById('template-editor-head');
  const templateEditorName = document.getElementById('template-editor-name');
  const templateEditorJSON = document.getElementById('template-editor-json');
  const issueFormGrid = document.getElementById('issue-form-grid');

  // templateEditor is set while the issue dialog edits a template. source is
  // the original template. The saved template keeps the fields hidden in the
  // builder.
  let templateEditor = null;

  function setTemplateMode(editor) {
    templateEditor = editor;
    const on = editor !== null;
    issueForm.classList.toggle('template-mode', on);
    syncIssueCatalog();
    templateEditorHead.hidden = !on;
    document.getElementById('issue-title').textContent = on ? (editor.source ? 'Edit template' : 'New template') : 'Issue credential';
    document.getElementById('issue-hint').textContent = on ? 'JSON shows every template field.' : 'Only the format is required.';
    issueSubmit.textContent = on ? 'Save template' : 'Issue';
    document.getElementById('template-editor-mode-builder').checked = true;
    templateEditorJSON.hidden = true;
    issueFormGrid.hidden = false;
  }

  function openTemplateEditor(tpl) {
    issueForm.reset();
    resetIssueFields();
    setTemplateMode({ source: tpl || null });
    templateEditorName.value = tpl ? tpl.name : '';
    if (tpl) applyTemplateToForm(tpl);
    templatesOverlay.classList.remove('active');
    issueOverlay.classList.add('active');
    fillIssueTemplateSelect();
    templateEditorName.focus();
  }

  // templateFromBuilder reads the template from the builder fields.
  function templateFromBuilder() {
    const source = (templateEditor && templateEditor.source) || {};
    const doc = Object.assign({}, source);
    delete doc.name;
    delete doc.predefined;
    doc.format = issueFormat.value;
    delete doc.vct;
    delete doc.doctype;
    const type = document.getElementById(doc.format === 'mdoc' ? 'issue-doctype' : 'issue-vct').value.trim();
    if (type) doc[doc.format === 'mdoc' ? 'doctype' : 'vct'] = type;
    const exp = document.getElementById('issue-exp').value.trim();
    if (exp) doc.exp = exp; else delete doc.exp;
    if (document.getElementById('issue-claims-mode-json').checked) {
      doc.claims = JSON.parse(issueClaimsTextarea.value.trim() || '{}');
    } else {
      doc.claims = builderClaims();
    }
    const fromRows = !document.getElementById('issue-claims-mode-json').checked;
    const always = doc.format !== 'sdjwt' ? [] : fromRows ? alwaysDisclosedFromRows() : alwaysDisclosedList();
    if (always.length > 0) doc.always_disclosed = always; else delete doc.always_disclosed;
    const display = {};
    const field = (id) => document.getElementById(id).value.trim();
    const fields = {
      name: 'issue-display-name', description: 'issue-display-description',
      background_color: 'issue-bg-color', text_color: 'issue-text-color',
      logo: 'issue-logo', logo_alt_text: 'issue-logo-alt', background_image: 'issue-bg-image',
    };
    for (const [key, id] of Object.entries(fields)) {
      if (field(id)) display[key] = field(id);
    }
    // The form leaves template images out. They stay unless the user sets new ones.
    const sourceDisplay = source.display || {};
    for (const key of ['logo', 'logo_alt_text', 'background_image']) {
      if (!display[key] && sourceDisplay[key]) display[key] = sourceDisplay[key];
    }
    if (Object.keys(display).length > 0) doc.display = display; else delete doc.display;
    const defaultName = display.name || templateEditorName.value.trim();
    const catalog = issueCatalog.entry(defaultName);
    if (catalog) doc.catalog = catalog; else delete doc.catalog;
    return doc;
  }

  function templateFromJSON() {
    const doc = JSON.parse(templateEditorJSON.value);
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
      throw new Error('expected a JSON object');
    }
    return doc;
  }

  function updateTemplateEditorMode() {
    const json = document.getElementById('template-editor-mode-json').checked;
    issueError.textContent = '';
    try {
      if (json) {
        templateEditorJSON.value = JSON.stringify(templateFromBuilder(), null, 2);
      } else {
        const doc = templateFromJSON();
        templateEditor.source = Object.assign({}, doc, { name: templateEditorName.value.trim() });
        applyTemplateToForm(doc);
        issueCatalog.reset();
        if (doc.catalog) issueCatalog.fill(doc.catalog);
      }
    } catch (e) {
      issueError.textContent = 'Template must be valid JSON: ' + e.message;
      document.getElementById(json ? 'template-editor-mode-builder' : 'template-editor-mode-json').checked = true;
      return;
    }
    templateEditorJSON.hidden = !json;
    issueFormGrid.hidden = json;
  }
  document.getElementById('template-editor-mode-builder').addEventListener('change', updateTemplateEditorMode);
  document.getElementById('template-editor-mode-json').addEventListener('change', updateTemplateEditorMode);

  // templateSaveRequest is the name and document of PUT api/templates/{name}
  // for the editor's values. It throws an Error with a message for the form.
  function templateSaveRequest() {
    const name = templateEditorName.value.trim();
    if (!name) throw new Error('Template name is required');
    let doc;
    try {
      doc = document.getElementById('template-editor-mode-json').checked ? templateFromJSON() : templateFromBuilder();
    } catch (e) {
      throw new Error('Template must be valid JSON: ' + e.message);
    }
    if (!document.getElementById('template-editor-mode-json').checked) {
      const problem = issueCatalog.validate((doc.display && doc.display.name) || name);
      if (problem) throw new Error(problem);
    }
    return { name, doc };
  }

  async function saveTemplateFromEditor() {
    let name, doc;
    try {
      ({ name, doc } = templateSaveRequest());
    } catch (e) {
      issueError.textContent = e.message;
      if (!templateEditorName.value.trim()) templateEditorName.focus();
      return;
    }
    if (!(await confirmTemplateName(name, templateEditor && templateEditor.source ? templateEditor.source.name : null))) return;
    issueSubmit.disabled = true;
    try {
      const resp = await fetch('api/templates/' + encodeURIComponent(name), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(doc)
      });
      const result = await resp.json();
      if (!resp.ok) {
        issueError.textContent = apiErrorText(result, resp);
        return;
      }
      templatesCache = null;
      setTemplateMode(null);
      issueOverlay.classList.remove('active');
      templatesOverlay.classList.add('active');
      await renderTemplatesList();
    } catch (e) {
      issueError.textContent = 'Request failed: ' + e.message;
    } finally {
      issueSubmit.disabled = false;
    }
  }

  // issueCommand is the API and CLI command for issuing with the form's values.
  function issueCommand(body) {
    const flags = [['--wallet'], ['--remote', eudiDialogs.remoteURL()]];
    // Linux takes at most 128 KiB in one argument. Large values go to files
    // first.
    const LARGE = 16 * 1024;
    const files = [];
    const steps = [];
    if (body.claims) {
      const claims = JSON.stringify(body.claims);
      if (claims.length > LARGE) {
        files.push('claims.json');
        steps.push('cat > claims.json' + eudiDialogs.heredoc(JSON.stringify(body.claims, null, 2)));
        flags.push(['--claims', '@claims.json']);
      } else {
        flags.push(['--claims', claims]);
      }
    }
    if (body.vct) flags.push(['--vct', body.vct]);
    if (body.doctype) flags.push(['--doc-type', body.doctype]);
    if (body.exp) flags.push(['--exp', body.exp]);
    if (body.nbf) flags.push(['--nbf', body.nbf]);
    if (body.batch) flags.push(['--batch', String(body.batch)]);
    if (body.unbound) flags.push(['--unbound']);
    if ('status_list_uri' in body) flags.push(['--status-list-uri', body.status_list_uri]);
    if (body.status_list_idx !== undefined) flags.push(['--status-list-idx', String(body.status_list_idx)]);
    if (body.always_disclosed) flags.push(['--always-disclosed', body.always_disclosed.join(',')]);
    if (body.save_as_template) flags.push(['--save-template', body.save_as_template]);
    const display = body.display || {};
    for (const [field, flag] of [['name', '--display-name'], ['description', '--display-description'],
      ['background_color', '--background-color'], ['text_color', '--text-color'], ['logo', '--logo'],
      ['logo_alt_text', '--logo-alt'], ['background_image', '--background-image']]) {
      const value = display[field];
      if (!value) continue;
      const image = /^data:image\/([a-z0-9.+-]+);base64,(.*)$/i.exec(value);
      if (image && value.length > LARGE) {
        const file = field.replace('_', '-') + '.' + image[1].replace('svg+xml', 'svg').replace('jpeg', 'jpg');
        files.push(file);
        steps.push('base64 -d > ' + file + eudiDialogs.heredoc(image[2].match(/.{1,76}/g).join('\n')));
        flags.push([flag, file]);
        continue;
      }
      flags.push([flag, value]);
    }
    if (body.display_template) flags.push(['--display-template', body.display_template]);
    if (body.catalog) flags.push(['--catalog', JSON.stringify(body.catalog)]);
    if (body.signing_key) flags.push(['--key', body.signing_key]);
    if (body.signing_cert) flags.push(['--cert', body.signing_cert]);
    const keyNote = body.signing_key ? 'The command holds the private signing key, so it ends up in your shell history.' : '';
    const notes = [];
    if (files.length) notes.push('The command first writes ' + files.join(', ') + ' to the current directory.');
    if (keyNote) notes.push(keyNote);
    return {
      curl: eudiDialogs.curl('POST', 'api/issue', body),
      note: keyNote,
      cli: (steps.length ? steps.join('\n') + '\n\n' : '') + eudiDialogs.cli('eudi issue ' + body.format, flags),
      cliNote: notes.join(' '),
    };
  }

  // templateCommand is the API and CLI command for saving the edited template.
  function templateCommand() {
    const { name, doc } = templateSaveRequest();
    return {
      curl: eudiDialogs.curl('PUT', 'api/templates/' + encodeURIComponent(name), doc),
      cli: eudiDialogs.cli('eudi templates import -', [['--name', name], ['--remote', eudiDialogs.remoteURL()]]) +
        eudiDialogs.heredoc(JSON.stringify(doc, null, 2)),
    };
  }

  eudiDialogs.setCommand(document.getElementById('issue-dialog'), () =>
    templateEditor ? templateCommand() : issueCommand(issueRequestBody()));

  async function renderTemplatesList() {
    let templates = [];
    try {
      templates = await loadTemplates(true);
    } catch (e) {
      templateError.textContent = 'Failed to load templates: ' + e.message;
      return;
    }
    templatesList.textContent = '';
    templates.forEach(tpl => {
      const row = document.createElement('div');
      row.className = 'template-row';
      row.id = 'template-row-' + tpl.name;
      row.dataset.templateName = tpl.name;
      row.dataset.predefined = tpl.predefined ? 'true' : 'false';

      const label = document.createElement('span');
      label.className = 'template-row-name';
      label.id = row.id + '-name';
      label.textContent = tpl.name;
      row.appendChild(label);

      const meta = document.createElement('span');
      meta.className = 'template-row-meta';
      meta.id = row.id + '-meta';
      meta.textContent = (tpl.format || 'any') + (tpl.predefined ? ' · predefined' : '');
      row.appendChild(meta);

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'btn btn-sm';
      editBtn.id = 'template-edit-' + tpl.name;
      editBtn.textContent = 'Edit';
      editBtn.addEventListener('click', () => openTemplateEditor(tpl));
      row.appendChild(editBtn);

      if (!tpl.predefined) {
        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'btn btn-sm';
        deleteBtn.id = 'template-delete-' + tpl.name;
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', async () => {
          templateError.textContent = '';
          try {
            const resp = await fetch('api/templates/' + encodeURIComponent(tpl.name), { method: 'DELETE' });
            if (!resp.ok) {
              const result = await resp.json();
              templateError.textContent = apiErrorText(result, resp);
              return;
            }
            await renderTemplatesList();
          } catch (e) {
            templateError.textContent = 'Request failed: ' + e.message;
          }
        });
        row.appendChild(deleteBtn);
      }

      templatesList.appendChild(row);
    });
  }

  function openTemplates() {
    templateError.textContent = '';
    templatesOverlay.classList.add('active');
    renderTemplatesList();
  }
  document.getElementById('templates-link').addEventListener('click', (event) => {
    event.preventDefault();
    openTemplates();
  });

  document.getElementById('template-new').addEventListener('click', () => openTemplateEditor(null));

  document.getElementById('template-close').addEventListener('click', () => {
    templatesOverlay.classList.remove('active');
  });

  async function loadLog() {
    const loadId = ++logLoadId;
    logLoading.hidden = logLoaded;
    logError.hidden = true;
    try {
      const resp = await fetch('api/log?view=activity');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const log = await resp.json();
      if (loadId !== logLoadId) return;
      renderLog(log);
      logLoaded = true;
    } catch (e) {
      if (loadId === logLoadId) logError.hidden = false;
      console.error('Failed to load log:', e);
    } finally {
      if (loadId === logLoadId) logLoading.hidden = true;
    }
  }

  document.getElementById('log-retry').addEventListener('click', loadLog);

  // Stop propagation so the drawer header does not toggle when this button is activated.
  const clearLogBtn = document.getElementById('clear-log-btn');
  clearLogBtn.addEventListener('keydown', (event) => event.stopPropagation());
  clearLogBtn.addEventListener('click', async (event) => {
    event.stopPropagation();
    try {
      await fetch('api/log', { method: 'DELETE' });
      await loadLog();
    } catch (e) {
      console.error('Failed to clear log:', e);
    }
  });

  const activityDrawer = document.getElementById('activity-drawer');
  const activityToggle = document.getElementById('activity-toggle');
  function setActivityCollapsed(collapsed) {
    activityDrawer.classList.toggle('collapsed', collapsed);
    activityToggle.setAttribute('aria-expanded', String(!collapsed));
    try { localStorage.setItem('activity-collapsed', collapsed ? '1' : '0'); } catch (e) { /* Storage may be unavailable in private browsing. */ }
  }
  try { if (localStorage.getItem('activity-collapsed') === '1') setActivityCollapsed(true); } catch (e) { /* Storage may be unavailable in private browsing. */ }
  const toggleActivity = () => setActivityCollapsed(!activityDrawer.classList.contains('collapsed'));
  activityToggle.addEventListener('click', toggleActivity);
  activityToggle.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggleActivity(); }
  });

  function renderLog(log) {
    logContainer.querySelectorAll('.log-entry').forEach(el => el.remove());
    if (!log || log.length === 0) {
      logEmpty.hidden = false;
      return;
    }
    logEmpty.hidden = true;

    combineRequestLogs(log).reverse().forEach((entry, index) => {
      const el = document.createElement('div');
      el.id = 'log-entry-' + index;
      const view = activityView(entry);
      const hasDetails = view.payload || view.presentations.length > 0 || Object.keys(view.details).length > 0;
      el.className = 'log-entry' + (hasDetails ? ' has-details' : '');
      el.dataset.testid = 'log-entry';
      el.dataset.event = entry.details?.event || '';
      el.dataset.action = entry.action;
      if (entry.details?.credential_id) el.dataset.credentialId = entry.details.credential_id;
      const time = new Date(entry.time).toLocaleTimeString();
      // Profile violations accepted in debug mode are warnings, separate from success and
      // failure.
      const warning = entry.severity === 'warning';
      const statusClass = warning ? 'warning' : (entry.success ? 'success' : 'failure');
      const statusLabel = warning ? '⚠ WARN' : (entry.success ? 'OK' : 'FAIL');
      let html = '<div class="log-header" id="' + el.id + '-header" data-testid="log-entry-toggle">' +
        '<span class="log-chevron" id="' + el.id + '-chevron">' + (hasDetails ? '▸' : '') + '</span>' +
        '<span class="log-time" id="' + el.id + '-time">' + time + '</span>' +
        '<span class="log-action ' + entry.action + '" id="' + el.id + '-action">' + escHtml(entry.action) + '</span>' +
        '<span class="log-detail" id="' + el.id + '-detail" title="' + escHtml(view.detail) + '">' + escHtml(view.detail) + '</span>' +
        '<span class="log-status ' + statusClass + '" id="' + el.id + '-status">' + statusLabel + '</span>' +
        '</div>';
      if (hasDetails) {
        html += '<div class="log-details" id="' + el.id + '-details">';
        if (Object.keys(view.details).length) html += renderLogDetails(view.details, el.id);
        if (view.payload) html += renderLogPayload(view.payload, view.decoderInput, view.presentations, view.credentials, el.id);
        else if (view.presentations.length) html += '<div class="log-payload-controls" id="' + el.id + '-controls">' + renderLogPresentations(view.presentations, el.id) + '</div>';
        html += '</div>';
      }
      el.innerHTML = html;
      if (hasDetails) {
        el.querySelector('.log-header').addEventListener('click', () => el.classList.toggle('expanded'));
      }
      const payloadToggle = el.querySelector('.log-payload-toggle');
      if (payloadToggle) {
        let showEncrypted = true;
        payloadToggle.addEventListener('click', () => {
          showEncrypted = !showEncrypted;
          el.querySelector('.log-payload > pre').textContent = logPayloadText(showEncrypted ? view.payload.wire : view.payload.body);
          el.querySelector('.log-payload-view').textContent = showEncrypted ? 'Encrypted view' : 'Decrypted view';
          payloadToggle.textContent = showEncrypted ? 'View decrypted' : 'View encrypted';
        });
      }
      logContainer.appendChild(el);
    });
  }

  const logKeyOrder = ['event', 'direction', 'source', 'method', 'url', 'status_code',
    'client_id', 'response_type', 'response_mode', 'response_uri', 'redirect_uri',
    'submission_uri', 'state', 'nonce'];

  function combineRequestLogs(log) {
    const entries = [];
    for (const entry of log) {
      if (entry.details?.event === 'presentation_request' && entry.success && typeof entry.payload?.body === 'string') {
        const index = entries.findLastIndex(candidate =>
          candidate.details?.event === 'request_object_fetch_response' && candidate.success &&
          !candidate.requestReceived && candidate.payload?.body === entry.payload.body);
        if (index !== -1) {
          const fetched = entries[index];
          entries[index] = {
            ...fetched,
            detail: entry.detail,
            details: { ...activityView(entry).details, ...fetched.details },
            requestReceived: true,
          };
          continue;
        }
      }
      entries.push(entry);
    }
    return entries;
  }

  function activityView(entry) {
    const details = { ...entry.details };
    const sentTokens = details.vp_token;
    delete details.sent_credentials;
    delete details.presented_credentials;
    let payload = entry.payload;
    let detail = entry.detail;
    let decoderInput;
    const event = details.event;
    if (event === 'presentation_response' || event === 'presentation_error_response') {
      if (!payload && details.browser_api_result) {
        const result = details.browser_api_result;
        if (typeof result.data?.response === 'string') {
          const body = {};
          for (const key of ['vp_token', 'id_token']) {
            if (details[key] !== undefined) body[key] = details[key];
          }
          payload = { label: 'Response', body: Object.keys(body).length ? body : null, encrypted: true, wire: result };
        } else {
          payload = { label: 'Response', body: result };
        }
      }
      if (!payload) {
        const body = {};
        for (const key of ['vp_token', 'id_token', 'state', 'error', 'error_description']) {
          if (details[key] !== undefined) body[key] = details[key];
        }
        if (Object.keys(body).length) payload = { label: 'Response parameters', body };
      }
      for (const key of ['vp_token', 'id_token', 'state', 'browser_api_result', 'error', 'error_description']) delete details[key];
    } else if (event === 'presentation_request' || event === 'interactive_authorization_presentation_request' || event === 'request_object_fetch_response') {
      if (details.request_object) {
        if (payload && typeof payload.body === 'string') decoderInput = payload.body;
        payload ||= { label: 'Request object (decoded)', body: details.request_object };
        for (const key of Object.keys(details.request_object)) delete details[key];
        delete details.request_object;
      }
    }
    for (const [key, label] of [['response_body', 'Response'], ['request', 'Request'], ['response', 'Response'], ['metadata', 'Response']]) {
      if (details[key] !== undefined) {
        if (payload && !entry.payload) continue;
        payload ||= { label, body: details[key] };
        if (key === 'request' && typeof details[key] === 'object' && details[key] !== null) {
          for (const field of Object.keys(details[key])) delete details[field];
          delete details.proof_jwt;
          delete details.proof_attestation;
        }
        delete details[key];
      }
    }
    if (event === 'credential_imported') {
      detail = 'Imported credential' + (details.credential_id ? ' ' + details.credential_id : '');
      const raw = details.raw_credential || details.credential?.raw;
      if (!payload && typeof raw === 'string') payload = { label: 'Credential', body: raw };
      if (typeof payload?.body === 'string') {
        payload = { ...payload, label: 'Credential' };
        decoderInput = payload.body;
      }
      delete details.raw_credential;
      delete details.credential;
    }
    if (event === 'request_object_fetch_response' && typeof payload?.body === 'string') decoderInput = payload.body;
    if (!payload && event === 'verifier_response') payload = { label: 'Response', body: '' };
    if (!payload && details.method && details.url) {
      payload = { label: 'Request', body: details.method + ' ' + details.url };
    }
    if (payload && event === 'token_request') {
      for (const key of ['grant_type', 'pre-authorized_code', 'tx_code']) delete details[key];
    }
    if (payload && event === 'nonce_response') delete details.c_nonce;
    if (payload && event === 'notification_request') {
      delete details.notification_id;
      delete details.notification_event;
    }
    if (payload && event === 'authorization_response') delete details.callback_values;
    const presentations = Object.entries(payload?.body?.vp_token || sentTokens || {}).flatMap(([queryID, tokens]) =>
      Array.isArray(tokens) ? tokens.flatMap((token, tokenIndex) =>
        typeof token === 'string' && token ? [{ queryID, token, tokenIndex }] : []) : []);
    const hasCredentials = event === 'credential_response' || event === 'deferred_credential_response' || event === 'credential_imported';
    let responseBody = payload?.body;
    if (hasCredentials && typeof responseBody === 'string') {
      try { responseBody = JSON.parse(responseBody); } catch (e) { responseBody = null; }
    }
    const credentials = hasCredentials && Array.isArray(responseBody?.credentials)
      ? responseBody.credentials.flatMap((credential, index) =>
        typeof credential?.credential === 'string' && credential.credential
          ? [{ token: credential.credential, index, id: credential.credential_id }] : [])
      : [];
    const copies = credentials.length > 1 ? ' (' + credentials.length + ' copies)' : '';
    if (event === 'credential_imported' && credentials.length) {
      detail = 'Imported credential' + copies;
      payload = { ...payload, label: 'Credential' + copies };
      decoderInput = undefined;
      details.primary_credential_id = details.credential_id;
      delete details.credential_id;
    } else if (copies) {
      detail += copies;
    }
    if (!decoderInput && !credentials.length && !presentations.length && !payload?.encrypted && isCompactJWT(payload?.body)) {
      decoderInput = payload.body.trim();
    }
    return { payload, detail, details, presentations, credentials, decoderInput };
  }

  function isCompactJWT(value) {
    return typeof value === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(~[A-Za-z0-9_.~-]*)?$/.test(value.trim());
  }

  function logPayloadText(value) {
    if (typeof value === 'string') {
      try {
        return JSON.stringify(JSON.parse(value), null, 2);
      } catch (e) {
        return value;
      }
    }
    return JSON.stringify(value, null, 2);
  }

  function renderLogPayload(payload, decoderInput, presentations, credentials, idPrefix) {
    const canToggle = payload.encrypted && payload.body != null && payload.wire !== undefined;
    const showWire = payload.encrypted && payload.wire !== undefined;
    let html = '<section class="log-payload" id="' + idPrefix + '-payload"><div class="log-payload-heading"><div class="log-payload-label" id="' + idPrefix + '-payload-label">' + escHtml(payload.label) + '</div>';
    if (payload.encrypted) {
      const view = showWire ? 'Encrypted view' : (payload.body != null ? 'Decrypted view' : 'Encrypted on wire');
      html += '<span class="log-payload-view" id="' + idPrefix + '-payload-view" title="Encrypted on the wire">' + view + '</span>';
    }
    html += '</div>';
    let controls = '';
    if (canToggle) controls += '<button type="button" class="btn log-payload-toggle" id="' + idPrefix + '-payload-toggle" data-testid="log-payload-toggle" title="Switch the log display between the wire value and plaintext">View decrypted</button>';
    if (decoderInput) controls += renderLogDecoderLink(decoderInput, idPrefix + '-decoder-link');
    if (presentations.length) controls += renderLogPresentations(presentations, idPrefix);
    credentials.forEach((credential, n) => {
      const label = credentials.length > 1 ? 'Open copy ' + (credential.index + 1) + ' in decoder' : 'Open in decoder';
      controls += renderLogDecoderLink(credential.token, idPrefix + '-credential-' + n, label, {
        'credential-index': credential.index,
        ...(credential.id ? { 'credential-id': credential.id } : {}),
      });
    });
    if (controls) html += '<div class="log-payload-controls" id="' + idPrefix + '-controls">' + controls + '</div>';
    const missing = payload.encrypted ? 'Plaintext unavailable' : 'No response body available';
    const value = showWire ? payload.wire : payload.body;
    const body = value == null ? missing : (value === '' ? '(empty body)' : logPayloadText(value));
    html += '<pre id="' + idPrefix + '-payload-body">' + escHtml(body) + '</pre>';
    if (payload.wire !== undefined && !payload.encrypted) {
      html += '<details class="log-wire" id="' + idPrefix + '-wire"><summary id="' + idPrefix + '-wire-toggle" data-testid="log-wire-toggle">Wire value</summary><pre id="' + idPrefix + '-wire-body">' + escHtml(logPayloadText(payload.wire)) + '</pre></details>';
    }
    return html + '</section>';
  }

  function renderLogDecoderLink(value, id, label = 'Open in decoder', attributes = {}) {
    const data = Object.entries(attributes).map(([key, val]) => ' data-' + key + '="' + escHtml(String(val)) + '"').join('');
    return '<a class="btn log-decoder-link" id="' + id + '" data-testid="log-decoder-link"' + data + ' href="decoder/#credential=' + encodeURIComponent(value) +
      '" target="_blank" rel="noopener">' + escHtml(label) + '</a>';
  }

  function renderLogPresentations(presentations, idPrefix) {
    let html = '';
    presentations.forEach((presentation, n) => {
      const label = "Open '" + presentation.queryID + "' in decoder" + (presentation.tokenIndex > 0 ? ' (' + (presentation.tokenIndex + 1) + ')' : '');
      html += renderLogDecoderLink(presentation.token, idPrefix + '-presentation-' + n, label, { 'query-id': presentation.queryID, 'token-index': presentation.tokenIndex });
    });
    return html;
  }

  function renderLogDetails(details, idPrefix) {
    const isObj = v => typeof v === 'object' && v !== null;
    const keys = Object.keys(details).sort((a, b) => {
      if (isObj(details[a]) !== isObj(details[b])) return isObj(details[a]) ? 1 : -1;
      const ia = logKeyOrder.indexOf(a), ib = logKeyOrder.indexOf(b);
      if (ia !== -1 || ib !== -1) return (ia === -1 ? logKeyOrder.length : ia) - (ib === -1 ? logKeyOrder.length : ib);
      return a.localeCompare(b);
    });
    let html = '<div class="log-fields" id="' + idPrefix + '-fields">';
    keys.forEach((key, n) => {
      const val = details[key];
      const field = idPrefix + '-field-' + n;
      html += '<span class="log-key" id="' + field + '-key">' + escHtml(key) + '</span>';
      if (isObj(val)) {
        html += '<span class="log-value" id="' + field + '-value"><pre id="' + field + '-json">' + escHtml(JSON.stringify(val, null, 2)) + '</pre></span>';
      } else {
        html += '<span class="log-value" id="' + field + '-value">' + escHtml(String(val)) + '</span>';
      }
    });
    html += '</div>';
    return html;
  }

  // The request ID lets a browser without cookies access its pending consent.
  function requestsURL() {
    return 'api/requests' +
      (openedForRequest ? '?request=' + encodeURIComponent(openedForRequest) : '');
  }

  // Hide the banner while a dialog covers it and refresh it when the dialog closes.
  function updatePendingBanner(requests) {
    const banner = document.getElementById('pending-banner');
    const pending = requests || [];
    if (pending.length === 0 || consentOverlay.classList.contains('active')) {
      banner.hidden = true;
      return;
    }
    // Unowned requests are available to all browsers. Label them separately from this
    // browser's requests.
    const claimed = pending.some((req) => req.mine);
    document.getElementById('pending-text').textContent = pending.length === 1
      ? (claimed ? 'A request is waiting for consent.' : 'A request from outside this browser is waiting for consent.')
      : pending.length + (claimed ? ' requests are waiting for consent.' : ' requests from outside this browser are waiting for consent.');
    banner.hidden = false;
  }

  async function refreshPendingBanner() {
    try {
      const resp = await fetch(requestsURL());
      const all = await resp.json();
      // Close consent answered elsewhere, but preserve this tab's dialog while its
      // submission is pending.
      if (consentRequestOpen && !consentSubmitting && consentRequestID != null &&
          !(all || []).some((req) => req.id === consentRequestID)) {
        closeConsentOverlay();
        return;
      }
      updatePendingBanner(reviewableRequests(all));
    } catch (e) {
      // Keep the current banner if refresh fails.
    }
  }

  // The server has already filtered requests by owner. Exclude the request currently shown
  // in a dialog.
  function reviewableRequests(requests) {
    return (requests || []).filter((req) => !(consentRequestOpen && req.id === consentRequestID));
  }

  document.getElementById('pending-review').addEventListener('click', async () => {
    try {
      const resp = await fetch(requestsURL());
      const requests = reviewableRequests(await resp.json());
      if (requests && requests.length > 0) {
        showConsentDialog(requests[0]);
        return;
      }
      updatePendingBanner(requests);
    } catch (e) {
      console.error('Failed to load pending requests:', e);
    }
  });

  async function loadPendingRequests() {
    try {
      const resp = await fetch(requestsURL());
      const requests = await resp.json();
      if (requests && requests.length > 0) {
        const own = requests.find((r) => r.id === openedForRequest) || requests.find((r) => r.mine);
        // Reconnecting must not reopen a dialog and reset a selection the user is editing.
        if (own && !consentRequestOpen) {
          showConsentDialog(own);
          return;
        }
        updatePendingBanner(reviewableRequests(requests));
        return;
      }
    } catch (e) {
      console.error('Failed to load pending requests:', e);
    }

    try {
      const resp = await fetch('api/error');
      presentError(await resp.json());
    } catch (e) {
      console.error('Failed to load last error:', e);
    }
  }

  function connectSSE() {
    const streamParams = new URLSearchParams({ tab: tabID });
    if (actingOwner) streamParams.set('owner', actingOwner);
    const es = new EventSource('api/requests/stream?' + streamParams);
    es.addEventListener('consent', (event) => {
      try {
        const req = JSON.parse(event.data);
        if (req.mine) {
          showConsentDialog(req);
          return;
        }
        refreshPendingBanner();
      } catch (e) {
        console.error('SSE parse error:', e);
      }
    });
    let stateRefresh = null;
    es.addEventListener('state', () => {
      // Issuance saves several times. Combine nearby events into one refresh.
      clearTimeout(stateRefresh);
      stateRefresh = setTimeout(() => {
        loadCredentials();
        loadDeferred();
        loadLog();
        refreshPendingBanner();
      }, 300);
    });
    // Issuer sign-in returns through /callback, which resumes the waiting issuance.
    es.addEventListener('authorize', (event) => {
      try {
        const { url } = JSON.parse(event.data);
        if (isWebURL(url)) window.location.href = url;
      } catch (e) {
        console.error('SSE authorize parse error:', e);
      }
    });
    es.addEventListener('wallet-error', (event) => {
      try {
        presentError(JSON.parse(event.data));
      } catch (e) {
        console.error('SSE wallet-error parse error:', e);
      }
    });
    es.addEventListener('open', () => {
      // SSE events are not replayed. A request created between the page load
      // and the opened stream comes from this fetch.
      document.body.dataset.requestStream = 'open';
      loadAppConfigPromise.then(loadPendingRequests);
    });
    es.onerror = () => {
      document.body.dataset.requestStream = 'closed';
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }

  // Clear stored errors before a new flow so they cannot appear over its consent dialog.
  function expectError() {
    dropStoredError();
  }

  // Reading an error does not consume it. Clear dismissed errors to prevent them from
  // reappearing.
  function dropStoredError() {
    fetch('api/error', { method: 'DELETE' }).catch(() => {});
  }

  // An error from an earlier request must not replace an active consent dialog.
  let consentRequestOpen = false;
  // Ignore late fetch results for dialogs that have been replaced.
  let consentRequestID = null;
  // The submitting handler closes its own dialog after receiving the result. Background
  // reconciliation must leave it open.
  let consentSubmitting = false;

  // Closing a dialog makes any request it replaced available in the banner again.
  function closeConsentOverlay() {
    eudiDialogs.setCommand(consentDialog, null);
    consentRequestOpen = false;
    consentRequestID = null;
    consentOverlay.classList.remove('active');
    refreshPendingBanner();
  }

  function presentError(err) {
    if (!err || !err.message) return;
    if (consentRequestOpen) {
      dropStoredError();
      return;
    }
    showErrorDialog(err.message, err.detail, err.findings);
  }

  // Go errors wrap their causes as "context: context: cause". The last part says
  // what went wrong. A very short last part reads better with the one before it,
  // as in "lookup example.invalid: no such host".
  function errorCause(detail) {
    const parts = String(detail).split(': ');
    if (parts.length < 2) return '';
    let cause = parts[parts.length - 1];
    if (cause.length < 20) cause = parts[parts.length - 2] + ': ' + cause;
    return cause.charAt(0).toUpperCase() + cause.slice(1);
  }

  // A wrapped error shows its cause. The full chain stays one click away.
  function errorDetailHtml(detail, id) {
    const cause = errorCause(detail);
    if (!cause) return '<pre class="error-detail" id="' + id + '">' + escHtml(detail) + '</pre>';
    return '<div class="dialog-message error-cause" id="' + id + '-cause">' + escHtml(cause) + '</div>' +
      '<details class="error-more" id="' + id + '-more"><summary id="' + id + '-more-toggle">Technical details</summary>' +
      '<pre class="error-detail" id="' + id + '">' + escHtml(detail) + '</pre></details>';
  }

  // showFlowError shows the error the wallet stored for this browser, so a
  // failed flow looks the same however the page learns of it. Without one it
  // shows the API answer.
  async function showFlowError(message, result, resp) {
    try {
      const stored = await (await fetch('api/error')).json();
      if (stored && stored.message) {
        presentError(stored);
        return;
      }
    } catch (e) { /* The API answer below still explains the failure. */ }
    showAPIError(message, result, resp);
  }

  // showAPIError shows a failed API call. A refusal lists its findings.
  function showAPIError(message, result, resp) {
    showErrorDialog(message, apiErrorText(result, resp), result && result.findings);
  }

  // A refusal lists its findings one by one. The full error text stays one
  // click away.
  function showErrorDialog(message, detail, findings) {
    eudiDialogs.setCommand(consentDialog, null);
    consentRequestOpen = false;
    const active = document.activeElement;
    const opener = active && active !== document.body && !consentDialog.contains(active) ? active : lastPageFocus;
    consentOverlay.classList.add('active');

    // The title takes the focus. A key typed for another field then can't
    // dismiss an unread error.
    var html = '<div class="dialog-title" id="error-title" tabindex="-1" style="color:var(--red)">Error</div>' +
      '<div class="dialog-message" id="error-message">' + escHtml(message) + '</div>';

    if (findings && findings.length) {
      html += '<ul class="error-findings" id="error-findings">' +
        findings.map((f, i) => '<li id="error-finding-' + i + '">' + escHtml(f) + '</li>').join('') + '</ul>';
      if (detail) {
        html += '<details class="error-more" id="error-detail-more"><summary id="error-detail-more-toggle">Technical details</summary>' +
          '<pre class="error-detail" id="error-detail">' + escHtml(detail) + '</pre></details>';
      }
    } else if (detail) {
      html += errorDetailHtml(detail, 'error-detail');
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-primary" id="error-dismiss" data-dialog-close>Dismiss</button>' +
    '</div>';

    consentDialog.innerHTML = html;
    const dismiss = document.getElementById('error-dismiss');
    dismiss.addEventListener('click', () => {
      closeConsentOverlay();
      fetch('api/error', { method: 'DELETE' }).catch(() => {});
      loadLog();
      if (opener && opener.isConnected && opener.offsetParent !== null) opener.focus();
    });
    document.getElementById('error-title').focus();
  }

  // Links and redirects built from data accept only web URLs. javascript: and data:
  // URLs could execute content in the wallet origin.
  function isWebURL(url) {
    if (!url) return false;
    try {
      const scheme = new URL(url, window.location.href).protocol;
      return scheme === 'http:' || scheme === 'https:';
    } catch (e) {
      return false;
    }
  }

  // OpenID4VP 1.0 §8.2: the wallet follows a redirect_uri from the verifier, both after
  // an Authorization Response and after an Authorization Error Response.
  function followVerifierRedirect(result) {
    if (!result.redirect_uri) return false;
    if (!isWebURL(result.redirect_uri)) {
      console.error('refusing to navigate to', result.redirect_uri);
      return false;
    }
    // The page navigates away, so only the console keeps the error.
    if (result.error) console.warn('wallet error before the redirect:', result.error);
    window.location.href = result.redirect_uri;
    return true;
  }

  function showSubmissionResult(result) {
    if (!result.error && followVerifierRedirect(result)) return;
    eudiDialogs.setCommand(consentDialog, null);

    consentOverlay.classList.add('active');

    var isSuccess = result.status_code && result.status_code < 400 && !result.error;
    var titleColor = isSuccess ? 'var(--green)' : 'var(--red)';
    var titleText = isSuccess ? 'Success' : 'Verifier Error';

    var html = '<div class="dialog-title" id="result-title" style="color:' + titleColor + '">' + titleText + ' (HTTP ' + (result.status_code || '?') + ')</div>';

    if (result.error) {
      var errorBody = result.error;
      try {
        var parsed = JSON.parse(errorBody);
        errorBody = JSON.stringify(parsed, null, 2);
      } catch (e) { /* Keep values that cannot be decoded unchanged. */ }
      html += '<pre class="error-detail" id="result-detail">' + escHtml(errorBody) + '</pre>';
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-primary" id="result-dismiss" data-dialog-close>Dismiss</button>' +
    '</div>';

    consentDialog.innerHTML = html;
    document.getElementById('result-dismiss').addEventListener('click', () => {
      closeConsentOverlay();
      loadLog();
    });
  }


  // Offer previews have no credential yet, so signature, status and holder binding checks
  // do not apply.
  function offerCardHtml(cred) {
    const fmt = cred.format ? formatLabelFor(cred) : '';
    const typeLabel = cred.vct || cred.doctype || cred.id;
    const display = cred.display || {};
    const prefix = 'offer-credential-' + domID(cred.id);
    const logoImg = display.logo_uri
      ? '<img class="credential-logo" id="' + prefix + '-logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
      : '';
    const faceBadge = fmt ? '<span class="format-badge format-badge-face" id="' + prefix + '-face-format">' + fmt + '</span>' : '';
    const rowBadge = fmt ? '<span class="format-badge format-badge-row" id="' + prefix + '-format">' + fmt + '</span>' : '';
    const faceName = cred.name || typeLabel;
    const nameHtml = '<span class="credential-name" id="' + prefix + '-name">' + escHtml(faceName) + '</span>';
    const typeMeta = cred.name
      ? '<div class="cred-meta"><span class="cred-meta-item"><span class="cred-meta-k" id="' + prefix + '-meta-type-key">type</span> <span class="mono" id="' + prefix + '-meta-type">' + escHtml(typeLabel) + '</span></span></div>'
      : '';
    const card = '<div class="credential-card">' +
        '<div class="card-face" id="' + prefix + '-face">' + faceBadge + logoImg + '<div class="face-name" id="' + prefix + '-face-name">' + escHtml(faceName) + '</div></div>' +
        '<div class="credential-info" id="' + prefix + '-info">' +
          '<div class="credential-type cred-hdr">' + rowBadge + nameHtml + '</div>' +
          typeMeta +
          (cred.description
            ? '<div class="offer-description" id="offer-description-' + domID(cred.id) + '">' + linkifyText(cred.description, 'offer-description-' + domID(cred.id)) + '</div>' +
              '<button type="button" class="link-btn offer-description-toggle" id="offer-description-' + domID(cred.id) + '-toggle" aria-expanded="false">More</button>'
            : '') +
        '</div>' +
      '</div>';
    let claims = '';
    if (cred.claims && cred.claims.length > 0) {
      claims = '<div class="cl-hd" id="' + prefix + '-claims-title">↗ You will receive<span class="cl-count" id="' + prefix + '-claims-count">' + cred.claims.length +
          ' claim' + (cred.claims.length === 1 ? '' : 's') + '</span></div>' +
        '<div class="consent-claims offer-claims" id="' + prefix + '-claims">' + cred.claims.map((claim, i) => {
          const row = prefix + '-claim-' + i;
          const label = (cred.claim_display_names || {})[claim];
          const path = '<span class="consent-claim-name mono" id="' + row + '">' + escHtml(claim).replace(/\./g, '.<wbr>') + '</span>';
          return label
            ? '<div class="consent-claim offer-claim-labeled"><span class="offer-claim-label" id="' + row + '-label">' + escHtml(label) + '</span>' + path + '</div>'
            : '<div class="consent-claim">' + path + '</div>';
        }).join('') + '</div>';
    }
    return '<div class="consent-credential" id="' + prefix + '" data-config-id="' + domID(cred.id) + '">' + card + claims + '</div>';
  }

  // A long issuer description stays at two lines until the user opens it.
  document.addEventListener('click', (event) => {
    const toggle = event.target.closest('.offer-description-toggle');
    if (!toggle) return;
    const open = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.previousElementSibling.classList.toggle('offer-description-open', open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.textContent = open ? 'Less' : 'More';
  });

  function renderOfferDetails(req) {
    const details = req.offer_details || {};
    let html = '';

    const facts = [];
    if (details.grant) facts.push(['Flow', details.grant]);
    if (facts.length > 0) {
      html += '<div class="offer-facts" id="offer-facts">' + facts.map(([k, v], i) =>
        '<div id="offer-fact-' + i + '"><span class="offer-fact-name" id="offer-fact-' + i + '-name">' + escHtml(k) + '</span>' +
        '<span class="offer-fact-value" id="offer-fact-' + i + '-value">' + escHtml(v) + '</span></div>'
      ).join('') + '</div>';
    }

    // The issuer sends the transaction code separately. Collect it before approving the
    // offer.
    if (details.tx_code) {
      const numeric = details.tx_code_input_mode !== 'text';
      html += '<div class="offer-tx-code" id="offer-tx-code">' +
        '<label for="offer-tx-code-input" id="offer-tx-code-label">Transaction code</label>' +
        '<input type="text" id="offer-tx-code-input" autocomplete="one-time-code"' +
        (numeric ? ' inputmode="numeric" pattern="[0-9]*"' : '') +
        (details.tx_code_length ? ' maxlength="' + escHtml(details.tx_code_length) + '"' : '') +
        ' placeholder="' + escHtml(details.tx_code_hint || 'code from the issuer') + '">' +
        (details.tx_code_description
          ? '<p class="dialog-hint" id="offer-tx-code-description">' + escHtml(details.tx_code_description) + '</p>'
          : '') +
      '</div>';
    }

    if (details.resolve_error) {
      html += '<p class="dialog-message" id="offer-resolve-error">The wallet could not fetch the offer, so it does not know the issuer yet. Approve to try again.</p>' +
        errorDetailHtml(details.resolve_error, 'offer-resolve-error-detail');
      return html;
    }

    const credentials = details.credentials || [];
    if (credentials.length === 0) {
      (req.offer_configs || []).forEach((cfg, i) => {
        html += '<div class="consent-credential" id="offer-config-' + i + '"><div class="consent-credential-header">' +
          '<span id="offer-config-' + i + '-name" style="font-size:12px;font-weight:600;">' + escHtml(cfg) + '</span>' +
          '</div></div>';
      });
      return html;
    }

    credentials.forEach(cred => { html += offerCardHtml(cred); });

    if (details.metadata_error) {
      html += '<p class="dialog-hint" id="offer-metadata-error">Issuer metadata unavailable. ' +
        'Showing only offer details.</p>';
    }
    return html;
  }

  const DEMO_CONSENT_NOTE = 'This public demo answers consent requests only from its web UI, unless the operator starts it with --demo-consent-api. ';

  function showConsentDialog(req) {
    consentRequestOpen = true;
    consentRequestID = req.id;
    consentSubmitting = false;
    dropStoredError();
    consentOverlay.classList.add('active');
    refreshPendingBanner();

    const isIssuance = req.type === 'issuance';

    const options = !isIssuance && req.credential_options &&
      (req.credential_options.queries || []).length > 0 ? req.credential_options : null;
    const selection = { editing: false, setChoices: [], picks: {}, claims: {}, claimSets: {}, showNonMatching: {}, showClaimSets: {} };
    let submitting = false;
    // An optional set answered only by non-matching credentials starts skipped,
    // because auto-accept skips it too.
    function defaultSetChoices(opts) {
      return (opts.sets || []).map(set =>
        set.optional && (set.unmatched || []).length === set.options.length ? -1 : 0);
    }
    // A credential used for two queries shares one merged disclosure selection.
    function defaultClaims() {
      const claims = {};
      options.queries.forEach(q => q.candidates.concat(q.non_matching || []).forEach(c => {
        const kept = claims[c.credential_id] || [];
        Object.keys(c.claims || {}).forEach(key => {
          if (!kept.includes(key)) kept.push(key);
        });
        claims[c.credential_id] = kept;
      }));
      return claims;
    }
    // A query with multiple: true presents every candidate unless the user
    // withholds some. Any other query presents its first candidate. A query with
    // only non-matching credentials has no automatic pick.
    function defaultPicks(q) {
      if (q.candidates.length === 0) return [];
      return q.multiple ? q.candidates.map(c => c.credential_id) : [q.candidates[0].credential_id];
    }
    if (options) {
      selection.setChoices = defaultSetChoices(options);
      options.queries.forEach(q => { selection.picks[q.id] = defaultPicks(q); });
      selection.claims = defaultClaims();
    }

    function queryById(id) { return options.queries.find(q => q.id === id); }
    function activeQueryIds() {
      if (!options.sets || options.sets.length === 0) return options.queries.map(q => q.id);
      const ids = [];
      options.sets.forEach((set, i) => {
        const choice = selection.setChoices[i];
        if (choice === -1) return;
        (set.options[choice] || []).forEach(id => { if (!ids.includes(id)) ids.push(id); });
      });
      return ids;
    }
    function activeCandidates(qid) {
      const q = queryById(qid);
      const picked = q.candidates.concat(q.non_matching || [])
        .filter(c => selection.picks[qid].includes(c.credential_id));
      if (picked.length > 0) return picked;
      return q.candidates.length > 0 ? [q.candidates[0]] : [];
    }
    function nonMatchingLabel(n) {
      return n + ' non-matching';
    }
    // A credential counts once, and only when it matches no query.
    function nonMatchingCount() {
      const matching = new Set(options.queries.flatMap(q => q.candidates.map(c => c.credential_id)));
      return new Set(options.queries.flatMap(q => (q.non_matching || []).map(c => c.credential_id))
        .filter(id => !matching.has(id))).size;
    }
    function hasAlternatives() {
      if (!options) return false;
      if ((options.sets || []).some(s => s.options.length > 1 || s.optional)) return true;
      return options.queries.some(q => q.candidates.length > 1 || (q.non_matching || []).length > 0);
    }
    function unansweredQueries() {
      return options ? activeQueryIds().filter(qid => activeCandidates(qid).length === 0) : [];
    }
    // A query that sets multiple sends all its candidates, so they are not alternatives.
    function alternativeCount() {
      let n = 0;
      (options.sets || []).forEach(s => { n += s.options.length - 1 + (s.optional ? 1 : 0); });
      options.queries.forEach(q => { if (!q.multiple) n += q.candidates.length - 1; });
      return n;
    }
    function multipleNote(qid) {
      const q = queryById(qid);
      if (!q.multiple || q.candidates.length < 2) return '';
      const sent = activeCandidates(qid).length;
      return '<div class="consent-multiple-note" id="consent-multiple-' + domID(qid) + '">' +
        'The verifier accepts several credentials. The wallet sends ' + sent + ' of ' + q.candidates.length + ' matching credentials.</div>';
    }
    // The dialog offers every claim_sets option satisfied by the picked
    // credentials. The first is the automatic choice.
    function claimSetOptions(qid) {
      const picked = activeCandidates(qid);
      if (picked.length === 0) return [];
      return (picked[0].claim_sets || []).filter(set =>
        picked.every(c => (c.claim_sets || []).some(other => other.index === set.index)));
    }
    function chosenClaimSet(mc) {
      const index = selection.claimSets[mc.query_id];
      if (index === undefined) return null;
      return (mc.claim_sets || []).find(set => set.index === index) || null;
    }
    // After the picks change, keep a claim set choice only while every picked
    // credential satisfies it, and disclose its claims on each of them.
    function syncClaimSetChoice(qid) {
      const index = selection.claimSets[qid];
      if (index === undefined) return;
      if (!claimSetOptions(qid).some(set => set.index === index)) {
        delete selection.claimSets[qid];
        const defaults = defaultClaims();
        activeCandidates(qid).forEach(c => {
          selection.claims[c.credential_id] = defaults[c.credential_id].slice();
        });
        return;
      }
      activeCandidates(qid).forEach(c => {
        selection.claims[c.credential_id] = c.claim_sets.find(set => set.index === index).keys.slice();
      });
    }
    // The note says which claim set the wallet sends, and the credential below
    // lists the claims of that set. Show all claim sets lists the other
    // matching sets.
    function claimSetPicker(qid) {
      const sets = claimSetOptions(qid);
      if (sets.length < 2) return '';
      const current = selection.claimSets[qid] === undefined ? sets[0].index : selection.claimSets[qid];
      const position = Math.max(1, sets.findIndex(set => set.index === current) + 1);
      const open = Boolean(selection.showClaimSets[qid]);
      const id = 'consent-claim-set-' + domID(qid);
      let html = '<div class="consent-multiple-note consent-claim-set" id="consent-claim-set-row-' + domID(qid) + '">' +
        '<span id="' + id + '-current">The verifier accepts ' + sets.length + ' claim sets. The wallet sends ' +
          (position === 1 ? 'the first' : 'set ' + position) + '.</span> ' +
        '<button type="button" class="link-btn consent-claim-set-toggle" id="consent-show-claim-sets-' + domID(qid) + '" data-query="' + escHtml(qid) + '" aria-expanded="' + open + '" aria-controls="' + id + '">' +
          (open ? 'Hide claim sets' : 'Show all claim sets') + '</button>';
      if (open) {
        html += '<div class="consent-claim-set-options" role="radiogroup" id="' + id + '" aria-labelledby="' + id + '-current">' +
          sets.map((set, i) =>
            '<label class="consent-claim-set-option" id="' + id + '-' + set.index + '-label">' +
              '<input type="radio" name="' + id + '" id="' + id + '-' + set.index + '" value="' + set.index + '" data-query="' + escHtml(qid) + '"' + (set.index === current ? ' checked' : '') + '>' +
              '<span class="consent-claim-set-text">' +
                '<span class="consent-claim-set-name">Set ' + (i + 1) + (i === 0 ? ' (auto)' : '') + '</span> ' +
                '<span class="consent-claim-set-keys">' + set.keys.map((key, k) =>
                  '<span class="consent-claim-set-key">' + escHtml(key) + (k < set.keys.length - 1 ? ',' : '') + '</span>').join(' ') + '</span>' +
              '</span>' +
            '</label>').join('') +
          '</div>';
      }
      return html + '</div>';
    }
    function isAutoSelection() {
      const defaultChoices = defaultSetChoices(options);
      return Object.keys(selection.claimSets).length === 0 &&
        selection.setChoices.every((c, i) => c === defaultChoices[i]) &&
        options.queries.every(q => {
          const auto = defaultPicks(q);
          const picks = selection.picks[q.id];
          return picks.length === auto.length && auto.every(id => picks.includes(id));
        });
    }
    // Load full credentials when Edit opens. Show the request summary while they load.
    let loadingCandidates = false;
    function candidateIds() {
      const ids = [];
      const add = id => { if (id && !ids.includes(id)) ids.push(id); };
      if (options) {
        options.queries.forEach(q => q.candidates.concat(q.non_matching || []).forEach(c => add(c.credential_id)));
      } else if (req.matched_credentials) {
        req.matched_credentials.forEach(mc => add(mc.credential_id));
      }
      return ids;
    }
    function ensureCandidateDetails() {
      if (loadingCandidates) return;
      const ids = candidateIds().filter(id => !candidateDetails.has(id));
      if (ids.length === 0) return;
      loadingCandidates = true;
      loadCandidateDetails(ids).then(loaded => {
        loadingCandidates = false;
        if (loaded && consentRequestOpen && consentRequestID === req.id) renderDialog();
      });
    }

    // Keep the authenticated identifier separate from the self-asserted display name.
    function whoBlock() {
      let name, cid, chip = '', logoHtml = '';
      if (isIssuance) {
        const d = req.offer_details || {};
        name = d.resolve_error ? 'Offer not fetched' : (d.issuer_name || '');
        cid = d.resolve_error ? (d.offer_uri || req.client_id || '') : (d.issuer || req.client_id || '');
        if (d.issuer_logo) {
          logoHtml = '<img class="who-logo" id="consent-who-logo" src="' + escHtml(d.issuer_logo) + '" alt="' + escHtml((name || 'Issuer') + ' logo') + '">';
        }
      } else {
        name = req.registered_name || req.client_name || '';
        cid = req.client_id || '';
        const auth = req.client_auth;
        if (auth) {
          chip = auth.signed
            ? '<span class="who-chip who-ok" id="consent-who-auth" title="Signature matches the supplied key. Signer trust is unchecked.">✓ Signed</span>'
            : '<span class="who-chip who-bad" id="consent-who-auth" title="' + escHtml(auth.detail || 'Unsigned request. The sender is not authenticated.') + '">✗ Not authenticated</span>';
        }
      }
      const idLine = '<span class="mono" id="consent-who-id">' + escHtml(cid) + '</span>';
      let nameHtml, sub;
      if (name) {
        nameHtml = '<span class="who-name" id="consent-who-name">' + escHtml(name) + '</span>';
        sub = '<div class="who-cid" id="offer-issuer-origin">' + idLine + '</div>';
      } else {
        nameHtml = '<span class="who-name mono" id="offer-issuer-origin">' + escHtml(cid) + '</span>';
        sub = '';
      }
      return '<div class="who" id="consent-who">' + logoHtml + '<div class="who-text"><div class="who-nm">' + nameHtml + chip + '</div>' + sub + '</div></div>';
    }

    // Debug mode continues after failed checks. They stay one collapsed line
    // under the verifier or the issuer, so the dialog stays readable.
    function findingsBlock() {
      const findings = req.findings || [];
      if (findings.length === 0) return '';
      const subject = isIssuance ? 'this issuer' : 'this verifier';
      return '<details class="consent-findings" id="consent-findings">' +
        '<summary id="consent-findings-summary"><span class="ico-warn" aria-hidden="true"></span>' +
        findings.length + (findings.length === 1 ? ' finding about ' : ' findings about ') + subject + '</summary>' +
        '<ul id="consent-findings-list">' + findings.map((f, i) => '<li id="consent-finding-' + i + '">' + escHtml(f) + '</li>').join('') + '</ul>' +
        '</details>';
    }

    function headerHtml() {
      let html = '<div class="consent-title" id="consent-title">' + (isIssuance ? 'Credential offer' : 'Presentation request') + '</div>' +
        whoBlock() + findingsBlock();

      // Verifier purposes come from registration certificates in verifier_info (OpenID4VP
      // 1.0 §5.1).
      // ARF RPA_10: show the privacy policy with the intended use.
      const policies = isIssuance ? [] : (req.privacy_policies || []);
      const policyLinks = '<span class="consent-privacy-policies" id="consent-privacy-policies">' +
        policies.filter(isWebURL).map((url, idx) => '<a id="consent-privacy-policy-' + idx + '" href="' + escHtml(url) + '" title="' + escHtml(url) +
          '" target="_blank" rel="noopener noreferrer">' + (policies.length > 1 ? 'Privacy policy ' + (idx + 1) : 'Privacy policy') + ' ↗</a>').join('') +
        '</span>';
      const purposes = isIssuance ? [] : (req.purposes || []);
      purposes.forEach((text, idx) => {
        html += '<div class="consent-purpose" id="consent-purpose-' + idx + '">' +
          '<span class="consent-purpose-label consent-purpose-head" id="consent-purpose-' + idx + '-label">Purpose' +
          (idx === 0 && policies.length > 0 ? policyLinks : '') + '</span>' + escHtml(text) + '</div>';
      });
      if (purposes.length === 0 && policies.length > 0) {
        html += '<div class="consent-purpose" id="consent-privacy-policy-block">' + policyLinks + '</div>';
      }
      return html;
    }

    // Allow required claims to be unchecked so developers can test verifier behavior.
    // Keep warnings visible without hover because touch screens have no hover state.
    function warnMarker(hint, id) {
      return '<span class="consent-claim-hint" id="' + id + '-hint"><span class="consent-claim-warn" id="' + id + '-warn" aria-hidden="true">⚠</span>' + escHtml(hint) + '</span>';
    }

    // The claims in always are sent in any case, so their checkboxes are fixed.
    function claimChecklist(credID, claims, kept, emptyArrays, missing, always) {
      const keys = Object.keys(claims || {});
      const fixed = always || [];
      const isShared = k => fixed.includes(k) || (kept ? kept.includes(k) : true);
      const shared = keys.filter(isShared).length;
      const empties = emptyArrays || [];
      const missingList = missing || [];
      const total = keys.length + missingList.length;
      let rows = '';
      const prefix = 'consent-credential-' + credID;
      keys.forEach((key, i) => {
        // Selecting an array without its selectively disclosable elements reveals an empty
        // array.
        const empty = empties.includes(key);
        const val = empty ? '[]'
          : (typeof claims[key] === 'object' ? JSON.stringify(claims[key]) : String(claims[key]));
        const row = prefix + '-claim-' + i;
        const warn = empty ? warnMarker('Empty array disclosed. Use a null or index path for the values.', row) : '';
        const isFixed = fixed.includes(key);
        const fixedTitle = isFixed ? ' title="The issuer did not make this claim selectively disclosable, so it is always sent."' : '';
        rows += '<label class="consent-claim' + (isFixed ? ' consent-claim-fixed' : '') + '" id="' + row + '"' + fixedTitle + '>' +
          '<input type="checkbox" id="' + row + '-input"' + (isShared(key) ? ' checked' : '') + (isFixed ? ' disabled' : '') + ' data-cred="' + credID + '" data-claim="' + escHtml(key) + '">' +
          '<span class="consent-claim-name mono" id="' + row + '-name">' + escHtml(key) + '</span>' +
          '<span class="consent-claim-value mono" id="' + row + '-value">' + escHtml(val) + '</span>' + warn +
          (isFixed ? '<span class="consent-claim-fixed-tag" id="' + row + '-fixed">always sent</span>' : '') +
        '</label>';
      });
      // Debug mode includes missing claims so the mismatch remains visible.
      missingList.forEach((path, i) => {
        const row = prefix + '-missing-' + i;
        rows += '<div class="consent-claim consent-claim-missing" id="' + row + '">' +
          '<input type="checkbox" id="' + row + '-input" disabled aria-hidden="true">' +
          '<span class="consent-claim-name mono" id="' + row + '-name">' + escHtml(path) + '</span>' +
          '<span class="consent-claim-value mono" id="' + row + '-value">(not disclosed)</span>' +
          warnMarker('Not provided by the selected credential.', row) +
        '</div>';
      });
      if (total === 0) {
        return '<div class="cl-hd" id="' + prefix + '-claims-title">↗ Shared with the verifier<span class="cl-count" id="' + prefix + '-claims-count">no fields</span></div>' +
          '<div class="consent-claims-empty" id="consent-claims-empty-' + credID + '">None of the requested claims is in this credential. Only its always-disclosed claims are sent.</div>';
      }
      return '<div class="cl-hd" id="' + prefix + '-claims-title">↗ Shared with the verifier<span class="cl-count" id="' + prefix + '-claims-count">' +
          shared + ' of ' + total + ' field' + (total === 1 ? '' : 's') + '</span></div>' +
        '<div class="consent-claims" id="' + prefix + '-claims">' + rows + '</div>';
    }

    // Match details contain only requested claims. Use them until full credential details
    // arrive.
    function credentialCardHtml(mc) {
      const detail = candidateDetails.get(mc.credential_id);
      const cred = detail || {
        id: mc.credential_id, format: mc.format, vct: mc.vct, doctype: mc.doctype, claims: mc.claims,
      };
      const body = credentialCardBody(cred, 'summary-');
      const kept = options ? selection.claims[mc.credential_id] : null;
      const claimSet = options ? chosenClaimSet(mc) : null;
      return '<div class="consent-credential" id="consent-credential-' + mc.credential_id + '" data-credential-id="' + mc.credential_id + '" data-vct="' + escHtml(mc.vct || '') + '" data-doctype="' + escHtml(mc.doctype || '') + '">' +
        '<div class="credential-card' + (cred.batch ? ' batch' : '') + '">' + body.html + '</div>' +
        untrustedAuthorityNote(mc, 'consent-untrusted-' + mc.credential_id) + unboundNote(mc) + mismatchNote(mc, 'consent-mismatch-' + mc.query_id + '-' + mc.credential_id) +
        (claimSet
          ? claimChecklist(mc.credential_id, claimSet.claims, kept, null, null, mc.always_disclosed)
          : claimChecklist(mc.credential_id, mc.claims, kept, mc.empty_array_claims, mc.missing_claims, mc.always_disclosed)) +
      '</div>';
    }

    // Debug mode offers credentials that fail trusted_authorities. Explain the mismatch
    // before consent.
    function untrustedAuthorityNote(mc, id) {
      if (!mc || !mc.untrusted_authority) return '';
      return '<div class="consent-untrusted" role="note" id="' + domID(id) + '">⚠ Issuer not in the verifier\'s trusted authorities. Allowed in debug mode.</div>';
    }

    // Debug mode offers a credential without holder binding to a query that
    // requires it (OpenID4VP 1.0 §6.1).
    function unboundNote(mc) {
      if (!mc || !mc.unbound) return '';
      return '<div class="consent-untrusted" role="note" id="consent-unbound-' + domID(mc.credential_id) + '">⚠ No holder binding, but the query requires one. Sent anyway in debug mode.</div>';
    }


    // The wallet sends a non-matching credential when the user picks it. List every
    // reason so the expected verifier error is clear.
    function mismatchNote(mc, id) {
      if (!mc || !mc.mismatches || mc.mismatches.length === 0) return '';
      return '<div class="consent-mismatch" role="note" id="' + domID(id) + '">' +
        '<span class="consent-mismatch-title" id="' + domID(id) + '-title">⚠ Does not match the query.</span>' +
        '<ul>' + mc.mismatches.map((r, i) => '<li id="' + domID(id) + '-reason-' + i + '">' + escHtml(r) + '</li>').join('') + '</ul></div>';
    }
    function unansweredNote(qid) {
      return '<div class="consent-unanswered" role="note" id="consent-unanswered-' + domID(qid) + '">' +
        'No credential matches <span class="query-chip" id="consent-unanswered-' + domID(qid) + '-query">' + escHtml(qid) + '</span>. ' +
        'Debug mode can send a non-matching one. Choose it under Edit.</div>';
    }
    // A query with one possible answer shows its credential without a selector.
    function candidateRowHtml(qid, c, i, multi, selectable) {
      const picked = selection.picks[qid].includes(c.credential_id);
      const nonMatching = !!(c.mismatches && c.mismatches.length);
      // Full credential details are needed to show claims beyond those requested.
      const detail = candidateDetails.get(c.credential_id);
      const body = credentialCardBody(detail || {
        id: c.credential_id, format: c.format, vct: c.vct, doctype: c.doctype, claims: c.claims,
      }, 'candidate-' + escHtml(qid) + '-');
      const rowID = 'consent-candidate-' + escHtml(qid) + '-' + c.credential_id;
      const label = escHtml(c.vct || c.doctype || c.format);
      return '<div class="candidate' + (picked ? ' selected' : '') + (nonMatching ? ' nonmatching' : '') + (selectable ? '' : ' fixed') + '" id="consent-candidate-' + domID(qid) + '-' + c.credential_id + '" data-query="' + escHtml(qid) + '" data-cred="' + c.credential_id + '"' + (nonMatching ? ' data-non-matching="true"' : '') +
          (selectable ? ' tabindex="0" role="' + (multi ? 'checkbox' : 'radio') + '" aria-checked="' + picked + '" aria-label="' + label + '"' : '') + '>' +
        '<div class="candidate-row">' +
          (selectable ? '<input type="' + (multi ? 'checkbox' : 'radio') + '" id="' + rowID + '-input" name="consent-pick-' + escHtml(qid) + '"' + (picked ? ' checked' : '') + ' tabindex="-1" aria-hidden="true" aria-label="' + label + '">' : '') +
          '<div class="credential-card' + (detail && detail.batch ? ' batch' : '') + '">' + body.html + '</div>' +
          '<div class="candidate-actions">' +
            (!nonMatching && (multi || i === 0) ? '<span class="auto-chip" id="' + rowID + '-auto">auto</span>' : '') +
            (nonMatching ? '<span class="mismatch-chip" id="consent-mismatch-chip-' + domID(qid) + '-' + c.credential_id + '">no match</span>' : '') +
            // Open decoding in another tab to preserve pending consent.
            '<a class="btn btn-sm candidate-decode" id="consent-decode-' + domID(qid) + '-' + c.credential_id + '"' +
              ' href="decoder/?id=' + encodeURIComponent(c.credential_id) + '" target="_blank" rel="noopener"' +
              ' title="Open in decoder">Show</a>' +
          '</div>' +
        '</div>' + untrustedAuthorityNote(c, rowID + '-untrusted') + unboundNote(c) +
        mismatchNote(c, 'consent-mismatch-' + qid + '-' + c.credential_id) + '</div>';
    }

    function editScreenHtml() {
      let html = headerHtml() +
        '<div class="consent-selection-row" id="consent-selection-edit-row">Selection' +
        (isAutoSelection() ? '' : '<button class="link-btn" id="consent-selection-reset">reset to auto</button>') +
        '<button class="btn" id="consent-selection-done">Done</button></div>';

      (options.sets || []).forEach((set, i) => {
        if (set.options.length === 1 && !set.optional) return;
        html += '<div class="consent-sets" id="consent-set-' + i + '" data-set="' + i + '"><span class="consent-section-label" id="consent-set-' + i + '-label">The verifier accepts one of</span>';
        set.options.forEach((opt, j) => {
          html += '<label class="consent-set-option" id="consent-set-' + i + '-option-' + j + '-label">' +
            '<input type="radio" id="consent-set-' + i + '-option-' + j + '" name="consent-set-' + i + '" value="' + j + '"' + (selection.setChoices[i] === j ? ' checked' : '') + '>' +
            opt.map((id, k) => '<span class="query-chip" id="consent-set-' + i + '-option-' + j + '-query-' + k + '">' + escHtml(id) + '</span>').join(' + ') +
            ((set.unmatched || []).includes(j)
              ? ' <span class="mismatch-chip" id="consent-set-' + i + '-option-' + j + '-nomatch">no match</span>'
              : (j === 0 ? ' <span class="auto-chip" id="consent-set-' + i + '-option-' + j + '-auto">auto</span>' : '')) +
          '</label>';
        });
        if (set.optional) {
          // A presentation needs at least one credential, so the last selected set cannot
          // be skipped.
          const othersAnswered = selection.setChoices.some((c, j) => j !== i && c !== -1);
          html += '<label class="consent-set-option" id="consent-set-' + i + '-none-label">' +
            '<input type="radio" id="consent-set-' + i + '-none" name="consent-set-' + i + '" value="-1"' +
            (selection.setChoices[i] === -1 ? ' checked' : '') +
            (othersAnswered ? '' : ' disabled') +
            '><span class="query-chip" id="consent-set-' + i + '-none-query">none</span></label>';
        }
        html += '</div>';
      });

      activeQueryIds().forEach(qid => {
        const q = queryById(qid);
        // A query that sets multiple accepts any number of its candidates, at least one.
        const multi = !!q.multiple;
        const others = q.non_matching || [];
        const selectable = multi || q.candidates.length + others.length > 1;
        html += '<div class="consent-credential" id="consent-query-' + domID(qid) + '" data-query-id="' + domID(qid) + '"' +
          (multi ? ' data-multiple="true" role="group" aria-label="Credentials answering ' : (selectable ? ' role="radiogroup"' : ' role="group"') + ' aria-label="Credential answering ') + escHtml(qid) + '">' +
          '<div class="consent-credential-header" id="consent-query-' + domID(qid) + '-header">' +
            '<span class="query-id-label" id="consent-query-' + domID(qid) + '-label">' + escHtml(qid) + '</span>' +
            '<span class="candidate-count" id="consent-query-' + domID(qid) + '-count">' + (q.candidates.length === 0 ? 'no credential matches' : q.candidates.length +
              (q.candidates.length === 1 ? ' credential matches' : ' of your credentials match')) +
              (multi ? ' · send one or more' : '') + '</span>' +
          '</div>';
        q.candidates.forEach((c, i) => { html += candidateRowHtml(qid, c, i, multi, selectable); });
        if (others.length > 0) {
          // A picked non-matching credential, or no matching one, keeps the rows open.
          const forced = others.some(c => selection.picks[qid].includes(c.credential_id)) || q.candidates.length === 0;
          const open = forced || selection.showNonMatching[qid];
          if (forced) {
            html += '<div class="consent-nonmatching-label" id="consent-nonmatching-label-' + domID(qid) + '">' +
              others.length + (others.length === 1 ? ' credential does not match' : ' credentials do not match') + '</div>';
          } else {
            html += '<button type="button" class="link-btn consent-nonmatching-toggle" id="consent-show-nonmatching-' + domID(qid) + '" data-query="' + escHtml(qid) + '" aria-expanded="' + open + '">' +
              (open ? 'Hide ' : 'Show ') + nonMatchingLabel(others.length) + '</button>';
          }
          if (open) others.forEach((c, i) => { html += candidateRowHtml(qid, c, i, multi, selectable); });
        }
        html += '</div>';
      });

      return html;
    }

    function wireSelectionHandlers() {
      consentDialog.querySelectorAll('[data-credential-id], .candidate[data-cred]').forEach(el => {
        const id = el.dataset.credentialId || el.dataset.cred;
        const detail = candidateDetails.get(id);
        applyCredentialDisplay(el, detail && detail.display);
      });
      if (isIssuance && req.offer_details) {
        const byId = {};
        (req.offer_details.credentials || []).forEach(c => { byId[c.id] = c.display; });
        consentDialog.querySelectorAll('[data-config-id]').forEach(el => {
          applyCredentialDisplay(el, byId[el.dataset.configId]);
        });
      }

      const edit = document.getElementById('consent-edit-selection');
      if (edit) edit.addEventListener('click', () => { selection.editing = true; renderDialog(); });
      const done = document.getElementById('consent-selection-done');
      if (done) done.addEventListener('click', () => { selection.editing = false; renderDialog(); });
      const reset = document.getElementById('consent-selection-reset');
      if (reset) reset.addEventListener('click', () => {
        selection.setChoices = defaultSetChoices(options);
        selection.claimSets = {};
        options.queries.forEach(q => { selection.picks[q.id] = defaultPicks(q); });
        selection.claims = defaultClaims();
        renderDialog();
      });
      consentDialog.querySelectorAll('.consent-sets input[type="radio"]').forEach(radio => {
        radio.addEventListener('change', () => {
          const setIdx = Number(radio.closest('.consent-sets').dataset.set);
          selection.setChoices[setIdx] = Number(radio.value);
          renderDialog();
        });
      });
      consentDialog.querySelectorAll('.candidate:not(.fixed)').forEach(el => {
        const choose = () => {
          const qid = el.dataset.query;
          const picks = selection.picks[qid];
          if (queryById(qid).multiple) {
            const idx = picks.indexOf(el.dataset.cred);
            // A presentation answers the query with at least one credential.
            if (idx >= 0 && picks.length === 1) return;
            if (idx >= 0) picks.splice(idx, 1); else picks.push(el.dataset.cred);
            syncClaimSetChoice(qid);
            renderDialog();
          } else if (picks[0] !== el.dataset.cred) {
            selection.picks[qid] = [el.dataset.cred];
            syncClaimSetChoice(qid);
            renderDialog();
          }
        };
        el.addEventListener('click', choose);
        el.addEventListener('keydown', e => {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(); }
        });
      });
      // Stop link clicks from selecting the row. Selection would redraw the dialog before
      // navigation completes.
      consentDialog.querySelectorAll('.candidate-decode').forEach(link => {
        link.addEventListener('click', e => e.stopPropagation());
        link.addEventListener('keydown', e => e.stopPropagation());
      });
      consentDialog.querySelectorAll('.consent-nonmatching-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
          const qid = btn.dataset.query;
          selection.showNonMatching[qid] = btn.getAttribute('aria-expanded') !== 'true';
          renderDialog();
        });
      });
      consentDialog.querySelectorAll('.consent-claim-set-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
          const qid = btn.dataset.query;
          selection.showClaimSets[qid] = btn.getAttribute('aria-expanded') !== 'true';
          renderDialog();
        });
      });
      consentDialog.querySelectorAll('.consent-claim-set-options input[type="radio"]').forEach(radio => {
        radio.addEventListener('change', () => {
          const qid = radio.dataset.query;
          const index = Number(radio.value);
          if (index === claimSetOptions(qid)[0].index) delete selection.claimSets[qid];
          else selection.claimSets[qid] = index;
          // Changing the claim set discloses all of its claims again.
          activeCandidates(qid).forEach(c => {
            const set = (c.claim_sets || []).find(other => other.index === index);
            if (set) selection.claims[c.credential_id] = set.keys.slice();
          });
          renderDialog();
        });
      });
      if (options) {
        consentDialog.querySelectorAll('.consent-claim input[type="checkbox"]').forEach(cb => {
          cb.addEventListener('change', () => {
            const kept = selection.claims[cb.dataset.cred];
            const idx = kept.indexOf(cb.dataset.claim);
            if (cb.checked && idx < 0) kept.push(cb.dataset.claim);
            if (!cb.checked && idx >= 0) kept.splice(idx, 1);
          });
        });
      }

      consentDialog.querySelectorAll('.consent-credential').forEach(credEl => {
        const countEl = credEl.querySelector('.cl-count');
        const boxes = credEl.querySelectorAll('.consent-claims input[type="checkbox"]');
        if (!countEl || boxes.length === 0) return;
        const total = boxes.length;
        const update = () => {
          const checked = [...boxes].filter(b => b.checked).length;
          countEl.textContent = checked + ' of ' + total + ' field' + (total === 1 ? '' : 's');
        };
        boxes.forEach(b => b.addEventListener('change', update));
      });
    }

    function renderDialog() {
    // Redrawing during submission would create another enabled Approve button.
    if (submitting) return;
    let html = headerHtml();

    if (isIssuance) {
      html += renderOfferDetails(req);
    }

    if (!isIssuance) {
      ensureCandidateDetails();
    }

    if (!isIssuance && options) {
      if (hasAlternatives()) {
        const n = alternativeCount();
        const others = nonMatchingCount();
        const unanswered = unansweredQueries().length;
        html += '<div class="consent-selection-row" id="consent-selection-row">' +
          (unanswered > 0 && isAutoSelection()
            ? unanswered + (unanswered === 1 ? ' query needs' : ' queries need') + ' a pick' +
              (others > 0 ? ' · ' + nonMatchingLabel(others) : '')
            : isAutoSelection()
              ? 'Auto-selected' + (n > 0 ? ' · ' + n + (n === 1 ? ' alternative' : ' alternatives') : '') +
                (others > 0 ? ' · ' + nonMatchingLabel(others) : '')
              : 'Your selection') +
          '<button class="btn" id="consent-edit-selection">Edit</button></div>';
      }
      activeQueryIds().forEach(qid => {
        if (activeCandidates(qid).length === 0) {
          html += unansweredNote(qid);
          return;
        }
        html += multipleNote(qid);
        html += claimSetPicker(qid);
        activeCandidates(qid).forEach(c => { html += credentialCardHtml(c); });
      });
    } else if (!isIssuance && req.matched_credentials && req.matched_credentials.length > 0) {
      req.matched_credentials.forEach(mc => { html += credentialCardHtml(mc); });
    }

    if (options && selection.editing) {
      html = editScreenHtml();
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-danger" id="consent-deny">Deny</button>' +
      '<button class="btn btn-primary" id="consent-approve">Approve</button>' +
    '</div>';

    // A redraw replaces the focused control. Its replacement takes the focus.
    const focusedID = consentDialog.contains(document.activeElement) ? document.activeElement.id : '';
    consentDialog.innerHTML = html;
    const refocus = focusedID && document.getElementById(focusedID);
    if (refocus) refocus.focus();
    // The More button only shows for a description longer than two lines.
    consentDialog.querySelectorAll('.offer-description').forEach(desc => {
      if (desc.scrollHeight <= desc.clientHeight + 1) desc.nextElementSibling.hidden = true;
    });
    wireSelectionHandlers();
    if (unansweredQueries().length > 0) {
      const approve = document.getElementById('consent-approve');
      approve.disabled = true;
      approve.title = 'Pick a credential for every query first';
      if (!selection.editing) {
        approve.setAttribute('aria-describedby', unansweredQueries().map(qid => 'consent-unanswered-' + qid).join(' '));
      }
    }

    document.getElementById('consent-approve').addEventListener('click', async () => {
      // Validate the transaction code before sending an offer that might only be redeemed
      // once.
      const txCodeField = document.getElementById('offer-tx-code-input');
      if (txCodeField && !txCodeField.value.trim()) {
        txCodeField.classList.add('input-error');
        txCodeField.focus();
        return;
      }
      if (txCodeField) txCodeField.classList.remove('input-error');

      const approveBtn = document.getElementById('consent-approve');
      const denyBtn = document.getElementById('consent-deny');
      submitting = true;
      consentSubmitting = true;
      approveBtn.disabled = true;
      approveBtn.textContent = 'Submitting…';
      expectError();
      denyBtn.disabled = true;

      try {
        const approveBody = approveRequestBody();
        const resp = await fetch(approveURL(req.id, '/approve'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...tabHeaders },
          body: JSON.stringify(approveBody)
        });
        const result = await resp.json();
        // A nested presentation can replace the issuance dialog before approval returns.
        // Do not update the replacement with the earlier result.
        if (consentRequestID !== req.id) return;
        if (!resp.ok) {
          showAPIError('This request could not be answered', result, resp);
          return;
        }
        if (isIssuance) {
          if (result.pending) {
            closeConsentOverlay();
            await loadDeferred();
            await loadLog();
            return;
          }
          if (result.error || (result.status_code && result.status_code >= 400)) {
            showErrorDialog('Credential issuance failed', result.error || ('HTTP ' + result.status_code), result.findings);
            return;
          }
          closeConsentOverlay();
          await loadCredentials();
          await loadLog();
          return;
        }
        showSubmissionResult(result);
      } catch (e) {
        submitting = false;
        console.error('Approve failed:', e);
        if (consentRequestID !== req.id) return;
        showErrorDialog('Approve request failed', e.message);
      } finally {
        consentSubmitting = false;
      }
    });

    document.getElementById('consent-deny').addEventListener('click', async () => {
      consentSubmitting = true;
      try {
        const resp = await fetch(approveURL(req.id, '/deny'), { method: 'POST' });
        const result = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          showAPIError('This request could not be denied', result, resp);
          return;
        }
        if (followVerifierRedirect(result)) return;
      } catch (e) {
        showErrorDialog('Deny request failed', e.message);
        return;
      } finally {
        consentSubmitting = false;
      }
      closeConsentOverlay();
      await loadLog();
    });
    }


    // approveRequestBody is the body of POST api/requests/{id}/approve with the
    // dialog's choices. With alternatives the dialog has no claim checkboxes,
    // so the body uses the tracked selection.
    function approveRequestBody() {
      if (isIssuance) {
        const txCodeInput = document.getElementById('offer-tx-code-input');
        return txCodeInput ? { tx_code: txCodeInput.value.trim() } : {};
      }
      const selected = {};
      if (options) {
        activeQueryIds().forEach(qid => {
          activeCandidates(qid).forEach(c => {
            selected[c.credential_id] = selection.claims[c.credential_id].slice();
          });
        });
      } else {
        consentDialog.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          if (cb.checked) {
            const credId = cb.dataset.cred;
            const claim = cb.dataset.claim;
            if (!selected[credId]) selected[credId] = [];
            selected[credId].push(claim);
          }
        });
      }
      const body = { selected_claims: selected };
      if (options) {
        body.picks = {};
        activeQueryIds().forEach(qid => {
          const ids = activeCandidates(qid).map(c => c.credential_id);
          body.picks[qid] = queryById(qid).multiple ? ids : ids[0];
        });
        body.set_choices = selection.setChoices.slice();
        const claimSets = {};
        activeQueryIds().forEach(qid => {
          if (selection.claimSets[qid] !== undefined) claimSets[qid] = selection.claimSets[qid];
        });
        if (Object.keys(claimSets).length > 0) body.claim_sets = claimSets;
      }
      return body;
    }

    // The command answers the newest pending request of this type with the
    // dialog's choices. A later request takes the same choices when it offers
    // the same credentials. ?request= lets a caller without this browser's
    // session answer it.
    eudiDialogs.setCommand(consentDialog, () => {
      const kind = { presentation: 'presentation request', issuance: 'credential offer', issuance_presentation: 'presentation request during issuance' }[req.type] || 'consent request';
      const find = 'REQUEST_ID="${REQUEST_ID:-$(curl -sS ' + eudiDialogs.shellQuote(eudiDialogs.walletURL('api/requests')) +
        " | jq -r '[.[] | select(.type == \"" + req.type + "\")] | sort_by(.created_at) | last | .id // empty')}\"\n" +
        ': "${REQUEST_ID:?no pending ' + kind + '}"';
      // The URL stays in single quotes. Only the variable is spliced in.
      const answer = (action, body) => eudiDialogs.curl('POST', 'api/requests/REQUEST_ID/' + action + '?request=REQUEST_ID', body)
        .replace(/REQUEST_ID/g, "'\"$REQUEST_ID\"'");
      const remote = ['--remote', eudiDialogs.remoteURL()];
      return {
        curl: '# The newest pending ' + kind + '. Set REQUEST_ID to answer another one.\n' + find +
          '\n\n# Approve\n' + answer('approve', approveRequestBody()) +
          '\n\n# Deny\n' + answer('deny'),
        note: (consentAPI ? '' : DEMO_CONSENT_NOTE) + 'The command needs jq. It answers the newest request that came from an API call, the CLI or a test. Requests opened in a browser are visible only in that browser. To answer this request, set REQUEST_ID=' + req.id + '.',
        cli: '# Approve the newest pending ' + kind + '\n' +
          eudiDialogs.cli('eudi wallet requests approve', [['--type', req.type], ['--body', '-'], remote]) +
          eudiDialogs.heredoc(JSON.stringify(approveRequestBody(), null, 2)) + '\n\n# Deny it\n' +
          eudiDialogs.cli('eudi wallet requests deny', [['--type', req.type], remote]),
        cliNote: (consentAPI ? '' : DEMO_CONSENT_NOTE) + 'Without an id, the command answers the newest request that came from an API call, the CLI or a test. Requests opened in a browser are visible only in that browser. To answer this request, put its id ' + req.id + ' after approve or deny.',
      };
    });
    renderDialog();
  }

  // Escape text and both quote characters because shared wallet values also appear in
  // attributes.
  function escHtml(s) {
    return String(s === undefined || s === null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // domID turns a value into an element id. Ids built from data hold only
  // these characters, so an id can't carry markup after the DOM decodes it.
  function domID(value) {
    return String(value).replace(/[^A-Za-z0-9_-]/g, '_');
  }

  // Escape descriptions and link only HTTP or HTTPS URLs. Escape href values to prevent
  // injected attributes.
  function linkifyText(s, idPrefix) {
    let n = 0;
    return escHtml(s).replace(/https?:\/\/[^\s<>"']+/g, function (url) {
      return '<a href="' + url + '" id="' + idPrefix + '-link-' + (n++) + '" target="_blank" rel="noopener">' + url + '</a>';
    });
  }

  // The public demo news opens once per content version. A consent link
  // never opens the news, so the news can't cover the request.
  const newsOverlay = document.getElementById('news-overlay');
  async function showNews(id) {
    const link = document.getElementById('news-link');
    const open = async () => {
      const resp = await fetch('api/news');
      if (!resp.ok) return;
      const content = document.getElementById('news-content');
      content.innerHTML = (await resp.json()).html;
      content.querySelectorAll('*').forEach((el, i) => { if (!el.id) el.id = 'news-content-' + i; });
      newsOverlay.classList.add('active');
      try { localStorage.setItem('news-seen', id); } catch (e) { /* Storage may be unavailable in private browsing. */ }
    };
    link.hidden = false;
    link.addEventListener('click', (event) => {
      event.preventDefault();
      open();
    });
    let seen = '';
    try { seen = localStorage.getItem('news-seen') || ''; } catch (e) { /* Storage may be unavailable in private browsing. */ }
    if (seen !== id && !openedForRequest && !actingOwner) open();
  }
  document.getElementById('news-close').addEventListener('click', () => {
    newsOverlay.classList.remove('active');
  });

  let demoMode = false;
  // consentAPI is false on a public demo that answers consent requests only
  // from this UI.
  let consentAPI = true;
  // protectedParties are registrations that public demo visitors can't
  // change.
  let protectedParties = new Set();
  // Wait for configuration before deciding to open consent automatically. The public demo uses
  // different ownership rules.
  // The server owns the limits and defaults of these fields.
  function applyFormDefaults(defaults) {
    const limit = (id, max) => { const el = document.getElementById(id); if (el && max) el.maxLength = max; };
    limit('issue-display-name', defaults.display_name_max);
    limit('issue-display-description', defaults.display_description_max);
    limit('issue-logo-alt', defaults.display_alt_text_max);
    const fill = (id, value, max) => {
      const el = document.getElementById(id);
      if (!el || !value) return;
      if (!el.value) el.value = value;
      el.placeholder = max ? 'Go duration, at most ' + max : el.placeholder;
    };
    fill('registrar-country', defaults.country);
    fill('registrar-registration-validity', defaults.registration_validity, defaults.registration_validity_max);
    fill('registrar-access-validity', defaults.access_validity, defaults.access_validity_max);
  }

  async function loadAppConfig() {
    try {
      const resp = await fetch('api/config');
      const config = await resp.json();
      if (config.version) window.EUDI_VERSION = config.version;
      window.eudiFooter(config);
      if (config.news_id) {
        showNews(config.news_id);
      }
      if (config.tls_listener === false) {
        // An external TLS terminator does not use the wallet's TLS certificate, so hide
        // that download.
        document.getElementById('tls-row-label').hidden = true;
        document.getElementById('tls-row').hidden = true;
      }
      applyFormDefaults(config.form_defaults || {});
      demoMode = !!(config.demo && config.demo.enabled);
      consentAPI = !demoMode || Boolean(config.demo.consent_api);
      protectedParties = new Set(config.protected_relying_parties || []);
      renderAutoAccept(!!config.auto_accept);
      renderConformance(config);
      ['conf-mode-select', 'conf-tls-select', 'conf-haip-input', 'conf-arf-input', 'conf-encrypted-input', 'conf-vci-version-select', 'conf-key-attestation-select', 'conf-vci-client-id'].forEach((id) => {
        const el = document.getElementById(id);
        if (el && !el.dataset.wired) {
          el.dataset.wired = '1';
          el.addEventListener('change', onConformanceChange);
        }
      });
      const confReset = document.getElementById('conf-reset');
      if (confReset && !confReset.dataset.wired) {
        confReset.dataset.wired = '1';
        confReset.addEventListener('click', resetConformance);
      }
      if (config.demo && config.demo.enabled) {
        demoMode = true;
        const note = document.getElementById('demo-note');
        const schedule = describeReset(config.demo);
        note.textContent = schedule
          ? 'Public demo, resets ' + schedule
          : 'Public demo, shared state';
        const bannerReset = document.getElementById('demo-banner-reset');
        bannerReset.textContent = schedule
          ? 'state resets ' + schedule
          : 'state is shared and never reset automatically';
        note.hidden = false;
        document.querySelectorAll('.issue-signing-field').forEach((el) => { el.hidden = true; });
        document.getElementById('clear-log-btn').hidden = true;
        if (!localStorage.getItem('demo-banner-dismissed')) {
          document.getElementById('demo-banner').hidden = false;
        }
        document.getElementById('demo-banner-dismiss').addEventListener('click', () => {
          localStorage.setItem('demo-banner-dismissed', '1');
          document.getElementById('demo-banner').hidden = true;
        });
        document.getElementById('demo-banner-cli-link').addEventListener('click', (event) => {
          event.preventDefault();
          cliOverlay.classList.add('active');
        });
      }
    } catch (e) {
      // The footer can load without optional server details.
    }
  }

  function renderAutoAccept(enabled) {
    const toggle = document.getElementById('auto-accept-toggle');
    toggle.hidden = demoMode && !enabled;
    toggle.disabled = demoMode;
    toggle.classList.toggle('btn-primary', enabled);
    toggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
    toggle.dataset.enabled = enabled ? '1' : '0';
    toggle.title = enabled
      ? 'This wallet approves every presentation and offer without asking.'
      : 'This wallet asks for consent before presenting or accepting.';
    if (!demoMode) {
      toggle.title += ' Click to change.';
    }
    if (!toggle.dataset.wired) {
      toggle.dataset.wired = '1';
      toggle.addEventListener('click', async () => {
        if (toggle.disabled) return;
        const next = toggle.dataset.enabled !== '1';
        try {
          const resp = await fetch('api/config/auto-accept', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: next }),
          });
          if (resp.ok) renderAutoAccept(next);
        } catch (e) {
          console.error('Changing auto-accept failed:', e);
        }
      });
    }
  }

  // Conformance settings apply to the wallet process. The public demo displays them without
  // allowing changes.
  let conformanceDefaults = { validation_mode: 'debug', require_haip: false, require_arf: false, require_encrypted_request: false, vci_version: '1.0', key_attestation_level: '' };

  function effectiveConformance() {
    return {
      mode: conformanceDefaults.validation_mode === 'strict' ? 'strict' : 'debug',
      tls: conformanceDefaults.tls_verify_override == null ? 'auto' : String(conformanceDefaults.tls_verify_override),
      haip: !!conformanceDefaults.require_haip,
      arf: !!conformanceDefaults.require_arf,
      encrypted: !!conformanceDefaults.require_encrypted_request,
      vciVersion: conformanceDefaults.vci_version === '1.1' ? '1.1' : '1.0',
      keyAttestationLevel: conformanceDefaults.key_attestation_level || '',
      vciClientID: conformanceDefaults.vci_client_id || '',
    };
  }

  function applyConformanceToControls() {
    const eff = effectiveConformance();
    const mode = document.getElementById('conf-mode-select');
    const tls = document.getElementById('conf-tls-select');
    const haip = document.getElementById('conf-haip-input');
    const arf = document.getElementById('conf-arf-input');
    const enc = document.getElementById('conf-encrypted-input');
    const vci = document.getElementById('conf-vci-version-select');
    const level = document.getElementById('conf-key-attestation-select');
    if (arf) { arf.checked = eff.arf; arf.disabled = demoMode; }
    if (tls) { tls.value = eff.tls; tls.disabled = demoMode; }
    if (mode) { mode.value = eff.mode === 'strict' ? 'strict' : 'debug'; mode.disabled = demoMode; }
    if (haip) { haip.checked = eff.haip; haip.disabled = demoMode; }
    if (enc) { enc.checked = eff.encrypted; enc.disabled = demoMode; }
    if (vci) { vci.value = eff.vciVersion; vci.disabled = demoMode; }
    if (level) { level.dataset.wanted = eff.keyAttestationLevel; level.value = eff.keyAttestationLevel; level.disabled = demoMode; }
    const clientID = document.getElementById('conf-vci-client-id');
    if (clientID) { clientID.value = eff.vciClientID; clientID.disabled = demoMode; }
    // The demo cannot change the client ID, so it shows only a fixed one.
    const clientIDRow = document.getElementById('conf-vci-client-id-row');
    if (clientIDRow) clientIDRow.hidden = demoMode && !eff.vciClientID;
    renderConformanceHints();
  }

  const CONFORMANCE_HINTS = {
    'conf-mode': { strict: 'Refuse', debug: 'Warn and continue' },
    'conf-tls': { auto: 'Verify in strict mode only', true: '', false: '' },
  };

  function renderConformanceHints() {
    for (const [id, hints] of Object.entries(CONFORMANCE_HINTS)) {
      const select = document.getElementById(id + '-select');
      const hint = document.getElementById(id + '-hint');
      if (select && hint) hint.textContent = hints[select.value] || '';
    }
  }

  function currentControlValues() {
    const mode = document.getElementById('conf-mode-select');
    const tls = document.getElementById('conf-tls-select');
    const haip = document.getElementById('conf-haip-input');
    const arf = document.getElementById('conf-arf-input');
    const enc = document.getElementById('conf-encrypted-input');
    const vci = document.getElementById('conf-vci-version-select');
    const level = document.getElementById('conf-key-attestation-select');
    const clientID = document.getElementById('conf-vci-client-id');
    return {
      validation_mode: mode ? mode.value : undefined,
      tls_verify_override: !tls || tls.value === 'auto' ? null : tls.value === 'true',
      require_haip: haip ? haip.checked : undefined,
      require_arf: arf ? arf.checked : undefined,
      require_encrypted_request: enc ? enc.checked : undefined,
      vci_version: vci ? vci.value : undefined,
      key_attestation_level: level ? level.value : undefined,
      vci_client_id: clientID ? clientID.value.trim() : undefined,
    };
  }

  async function setServerConformance(values) {
    try {
      const resp = await fetch('api/config/conformance', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values),
      });
      if (resp.ok) conformanceDefaults = Object.assign({}, conformanceDefaults, await resp.json());
    } catch (e) { /* Keep the selected values if saving fails. */ }
    applyConformanceToControls();
  }

  function onConformanceChange(event) {
    // The ARF builds on HAIP, so turning the ARF checks on turns HAIP on too.
    if (event && event.target && event.target.id === 'conf-arf-input' && event.target.checked) {
      const haip = document.getElementById('conf-haip-input');
      if (haip) haip.checked = true;
    }
    renderConformanceHints();
    if (demoMode) return;
    setServerConformance(currentControlValues());
  }

  function resetConformance() {
    if (demoMode) return;
    fetch('api/config/conformance', { method: 'DELETE' })
      .then((r) => (r.ok ? r.json() : null))
      .then((c) => { if (c) conformanceDefaults = Object.assign({}, conformanceDefaults, c); applyConformanceToControls(); })
      .catch(() => { applyConformanceToControls(); });
  }

  function renderConformance(config) {
    conformanceDefaults = config || conformanceDefaults;
    applyConformanceToControls();
    const set = (id, text, state) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = text;
      el.classList.toggle('conf-on', state === 'on');
      el.classList.toggle('conf-off', state === 'off');
    };
    set('conf-transcript', config.session_transcript === 'iso' ? 'ISO 18013-7' : 'OpenID4VP', 'neutral');
    set('conf-format', config.preferred_format || 'None',
      config.preferred_format ? 'neutral' : 'off');
    const intro = document.getElementById('conf-intro');
    if (intro) intro.hidden = !demoMode;
    const reset = document.getElementById('conf-reset');
    if (reset) reset.hidden = demoMode;
  }

  function describeReset(demo) {
    if (demo.reset_daily_at) return 'daily at ' + demo.reset_daily_at;
    const secs = demo.reset_interval_seconds || 0;
    return secs > 0 ? 'every ' + formatInterval(secs) : null;
  }

  function formatInterval(secs) {
    if (secs % 3600 === 0) {
      const h = secs / 3600;
      return h === 1 ? 'hour' : h + ' hours';
    }
    const m = Math.round(secs / 60);
    return m + ' minutes';
  }

  const TRUSTED_LIST_CA = 'trusted-list-ca';
  let trustEntityLists = [];
  // The provider popup lists the entity lists of the latest trust state.
  let trustLoaded = Promise.resolve();

  function trustRemoveButton(id, label, data) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-danger btn-sm trust-remove';
    button.id = id;
    button.title = 'Remove';
    button.setAttribute('aria-label', 'Remove ' + label);
    button.innerHTML = '&times;';
    button.addEventListener('click', async () => {
      const path = data.entity ? 'api/trust/entities/' + encodeURIComponent(data.entity) : 'api/trust/lists?url=' + encodeURIComponent(data.list);
      await changeTrust('DELETE', path, null, document.getElementById('trust-error'));
      document.getElementById('trust-title').focus();
    });
    return button;
  }

  function addedEntityList(id, entities) {
    const list = document.createElement('ul');
    list.className = 'trust-added';
    list.id = id;
    entities.forEach(e => {
      const item = document.createElement('li');
      item.id = 'trust-entity-' + domID(e.id);
      const name = document.createElement('span');
      name.id = item.id + '-name';
      name.textContent = e.name;
      item.append(name, trustRemoveButton(item.id + '-remove', e.name, { entity: e.id }));
      list.appendChild(item);
    });
    return list;
  }

  // Issuance can add trusted lists, so refresh links when credentials change.
  async function loadTrustLists() {
    const row = document.getElementById('trust-list-links');
    const error = document.getElementById('trust-error');
    let lists = [];
    let state = {};
    try {
      const doc = await (await fetch('api/trustlists')).json();
      lists = (doc && doc.trust_lists) || [];
      state = await registrarRequest('GET', 'api/trust');
    } catch (e) {
      error.textContent = e.message;
    }
    trustEntityLists = state.entity_lists || [];
    const added = state.entities || [];
    row.querySelectorAll('.trust-items').forEach(el => el.remove());

    const groups = new Map();
    lists.forEach(entry => {
      const category = entry.category || 'Other';
      if (!groups.has(category)) groups.set(category, []);
      groups.get(category).push(entry);
    });

    const list = document.createElement('dl');
    list.className = 'trust-items';
    list.id = 'trust-items';
    const group = (title, slug) => {
      const term = document.createElement('dt');
      term.id = 'trust-group-' + slug;
      term.textContent = title;
      const detail = document.createElement('dd');
      detail.id = 'trust-group-' + slug + '-lists';
      list.append(term, detail);
      return detail;
    };
    [...groups.keys()].sort().forEach(category => {
      const detail = group(category, domID(category.toLowerCase()));
      groups.get(category).forEach(entry => {
        const url = entry.advertised_url || entry.url ||
          (entry.path ? window.location.origin + entry.path : '');
        if (!isWebURL(url)) return;
        const prefix = 'trust-list-' + domID(entry.id || 'list');
        const links = document.createElement('span');
        links.className = 'trust-links';
        links.id = prefix;
        const link = document.createElement('a');
        link.id = prefix + '-link';
        link.href = url;
        link.textContent = entry.id || 'trusted list';
        link.title = url;
        links.appendChild(link);
        if (entry.entityName) {
          const name = document.createElement('span');
          name.className = 'trust-list-name';
          name.id = prefix + '-name';
          name.textContent = entry.entityName;
          links.appendChild(name);
        }
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'copy-btn';
        copy.id = prefix + '-copy';
        copy.textContent = '⧉';
        copy.title = 'Copy trusted list URL';
        copy.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(url);
            copy.textContent = '✓';
            setTimeout(() => { copy.textContent = '⧉'; }, 1200);
          } catch (e) { /* The clipboard API may be unavailable. */ }
        });
        links.appendChild(copy);
        detail.appendChild(links);
        if (entry.description) {
          const desc = document.createElement('span');
          desc.className = 'trust-item-hint';
          desc.id = prefix + '-hint';
          desc.textContent = entry.description;
          detail.appendChild(desc);
        }
        const mine = added.filter(e => e.list === entry.id);
        if (mine.length > 0) detail.appendChild(addedEntityList(prefix + '-added', mine));
      });
    });

    const operators = added.filter(e => e.list === TRUSTED_LIST_CA);
    const external = state.lists || [];
    if (operators.length > 0 || external.length > 0) {
      const detail = group('External lists', 'external');
      const items = document.createElement('ul');
      items.className = 'trust-added';
      items.id = 'trust-external-lists';
      external.forEach((l, i) => {
        const item = document.createElement('li');
        item.id = 'trust-external-' + i;
        const text = document.createElement('span');
        text.id = item.id + '-url';
        text.textContent = l.url;
        if (l.error) {
          const failure = document.createElement('span');
          failure.className = 'trust-list-error';
          failure.id = item.id + '-error';
          failure.textContent = 'Not used: ' + l.error;
          text.appendChild(failure);
        } else if (l.type && !l.direct) {
          const note = document.createElement('span');
          note.className = 'trust-item-hint';
          note.id = item.id + '-catalogue-hint';
          note.textContent = 'Used only through a catalogue entry that links it.';
          text.appendChild(note);
        }
        item.appendChild(text);
        if (l.via || l.configured) {
          const source = document.createElement('span');
          source.className = 'trust-list-name';
          source.id = item.id + '-source';
          source.textContent = l.via ? 'from ' + l.via : '--trusted-list';
          item.appendChild(source);
        } else {
          item.appendChild(trustRemoveButton(item.id + '-remove', l.url, { list: l.url }));
        }
        items.appendChild(item);
      });
      detail.appendChild(items);
      if (operators.length > 0) {
        const label = document.createElement('span');
        label.className = 'trust-item-hint';
        label.id = 'trust-operators-label';
        label.textContent = 'CAs of list operators (trusted-list-ca)';
        detail.append(label, addedEntityList('trust-operators', operators));
      }
    }
    row.appendChild(list);
  }

  async function changeTrust(method, path, body, error) {
    error.textContent = '';
    try {
      await registrarRequest(method, path, body);
      await loadTrustLists();
      return true;
    } catch (e) {
      error.textContent = e.message;
      return false;
    }
  }

  const trustOverlay = document.getElementById('trust-overlay');
  const trustProviderOverlay = document.getElementById('trust-provider-overlay');
  const trustExternalOverlay = document.getElementById('trust-external-overlay');
  function openTrustPopup(popup, focus) {
    popup.querySelector('.form-error').textContent = '';
    trustOverlay.classList.remove('active');
    popup.classList.add('active');
    document.getElementById(focus).focus();
  }
  function closeTrustPopup(popup, opener) {
    popup.classList.remove('active');
    trustOverlay.classList.add('active');
    document.getElementById(opener).focus();
  }
  async function openProviderPopup(list) {
    await trustLoaded;
    const select = document.getElementById('trust-entity-list');
    select.innerHTML = trustEntityLists.map(id => '<option value="' + escHtml(id) + '" id="trust-entity-list-' + domID(id) + '">' +
      escHtml(id === TRUSTED_LIST_CA ? TRUSTED_LIST_CA + ' (CA of a list operator, for external lists)' : id) + '</option>').join('');
    if (list) select.value = list;
    openTrustPopup(trustProviderOverlay, 'trust-entity-list');
  }
  document.getElementById('trust-add-provider').addEventListener('click', () => openProviderPopup());
  document.getElementById('trust-external-add-operator').addEventListener('click', () => {
    trustExternalOverlay.classList.remove('active');
    openProviderPopup(TRUSTED_LIST_CA);
  });
  document.getElementById('trust-add-list').addEventListener('click', () => openTrustPopup(trustExternalOverlay, 'trust-list-url'));
  document.getElementById('trust-provider-cancel').addEventListener('click', () => closeTrustPopup(trustProviderOverlay, 'trust-add-provider'));
  document.getElementById('trust-external-cancel').addEventListener('click', () => closeTrustPopup(trustExternalOverlay, 'trust-add-list'));
  document.getElementById('trust-provider-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const ca = document.getElementById('trust-entity-ca');
    const name = document.getElementById('trust-entity-name');
    if (await changeTrust('POST', 'api/trust/entities', {
      list: document.getElementById('trust-entity-list').value,
      name: name.value.trim(),
      certificates: ca.value,
    }, document.getElementById('trust-provider-error'))) {
      ca.value = '';
      name.value = '';
      closeTrustPopup(trustProviderOverlay, 'trust-add-provider');
    }
  });
  document.getElementById('trust-external-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = document.getElementById('trust-list-url');
    if (await changeTrust('POST', 'api/trust/lists', { url: input.value.trim() }, document.getElementById('trust-external-error'))) {
      input.value = '';
      closeTrustPopup(trustExternalOverlay, 'trust-add-list');
    }
  });
  document.getElementById('trust-link').addEventListener('click', (event) => {
    event.preventDefault();
    document.getElementById('trust-error').textContent = '';
    trustLoaded = loadTrustLists();
    trustOverlay.classList.add('active');
    document.getElementById('trust-title').focus();
  });
  document.getElementById('trust-close').addEventListener('click', () => {
    trustOverlay.classList.remove('active');
    document.getElementById('trust-link').focus();
  });

  const registrarValue = id => document.getElementById(id).value.trim();

  async function registrarRequest(method, path, body) {
    const resp = await fetch(path, {
      method: method,
      headers: body ? { 'Content-Type': 'application/json', 'Accept': 'application/json' } : { 'Accept': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const result = resp.status === 204 ? {} : await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(apiErrorText(result, resp));
    return result;
  }

  function wireCopyButton(button, field) {
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(field.value !== undefined ? field.value : field.textContent);
        button.textContent = 'Copied';
        setTimeout(() => { button.textContent = 'Copy'; }, 1200);
      } catch (e) { /* The clipboard API may be unavailable. */ }
    });
  }

  // Element IDs contain the registrar identifier, so tests can find a party by
  // the identifier from the API response.

  // A service provider counts as a verifier even before it has intended uses.
  const SERVICE_PROVIDER_ENTITLEMENT = 'https://uri.etsi.org/19475/Entitlement/Service_Provider';
  function serviceRoles(service) {
    const roles = [];
    if ((service.intendedUses || []).length > 0 || (service.entitlements || []).includes(SERVICE_PROVIDER_ENTITLEMENT)) roles.push('verifier');
    if ((service.providesAttestations || []).length > 0) roles.push('issuer');
    return roles;
  }
  function relyingPartyRoles(rp) {
    const roles = (rp.services || []).flatMap(serviceRoles);
    return ['verifier', 'issuer'].filter(role => roles.includes(role));
  }

  // A provided attestation has a type field. A registered credential has its
  // type in its DCQL meta.
  function registeredCredentialType(credential) {
    const meta = credential.meta || {};
    return credential.type || meta.doctype_value || (meta.vct_values || [])[0] || credential.format;
  }

  function registeredClaims(credential) {
    const type = registeredCredentialType(credential);
    // Show mdoc claims as the dialog expects them: element, or
    // namespace:element.
    return (credential.claims || []).map(c => {
      const path = c.path || [];
      if (credential.format !== FORMATS.MDOC || path.length !== 2) return path.join('.');
      return path[0] === type ? path[1] : path[0] + ':' + path[1];
    });
  }

  function registeredCredentialSummary(credential) {
    const type = registeredCredentialType(credential);
    const claims = registeredClaims(credential);
    return claims.length > 0 ? type + ': ' + claims.join(', ') : type;
  }

  // A registered credential is one line: its type, its format and its number
  // of claims. The claims open on click, so the list stays short for a
  // verifier with many credentials.
  function registeredCredentialItem(credential, id) {
    const type = registeredCredentialType(credential);
    const claims = registeredClaims(credential).join(', ');
    const count = (credential.claims || []).length;
    const head = '<span class="registrar-credential-type" id="' + id + '-type">' + escHtml(type) + '</span>' +
      '<span class="registrar-credential-meta" id="' + id + '-meta">' + escHtml(credential.format || '') +
      (count > 0 ? ' · ' + count + (count === 1 ? ' claim' : ' claims') : '') + '</span>';
    if (count === 0) return '<li id="' + id + '">' + head + '</li>';
    return '<li id="' + id + '"><details id="' + id + '-details"><summary id="' + id + '-summary">' + head + '</summary>' +
      '<div class="registrar-credential-claims" id="' + id + '-claims">' + escHtml(claims) + '</div></details></li>';
  }

  function registeredCredentialList(credentials, listID, itemID) {
    return '<ul class="registrar-use-credentials" id="' + listID + '">' +
      credentials.map((c, i) => registeredCredentialItem(c, itemID + '-' + i)).join('') +
      '</ul>';
  }

  const registrarPartiesOverlay = document.getElementById('registrar-parties-overlay');
  const registrarPartyList = document.getElementById('registrar-party-list');

  // Each intended use shows the status of its registration certificates like a
  // credential card: no certificate yet, active, or revoked on the registrar's
  // status list.
  let registrarStatuses = [];
  // The registrar keeps the current certificate, so its value comes from the
  // status list entries.
  function storedInfo(identifier, matches, field) {
    const current = registrarStatuses.filter(s => s.identifier === identifier && matches(s) && !s.superseded && s[field]);
    return current.length > 0 ? current[current.length - 1][field] : undefined;
  }
  // A superseded certificate was revoked for good, and its reason says what
  // changed. Only a new certificate helps then.
  function certificateStatus(entries) {
    if (entries.length === 0) return { status: 'none' };
    const current = entries.filter(s => !s.superseded);
    if (current.length === 0) {
      const reason = entries[entries.length - 1].reason;
      return { status: reason === 'expired' ? 'expired' : 'outdated', reason: reason };
    }
    if (current.every(s => s.expires && s.expires * 1000 < Date.now())) return { status: 'expired' };
    return { status: current.some(s => !s.revoked) ? 'active' : 'revoked' };
  }
  function intendedUseStatus(identifier, intendedUse) {
    return certificateStatus(registrarStatuses.filter(s => s.identifier === identifier && s.intendedUse === intendedUse));
  }
  // A provider certificate covers a service and has no intended use (ARF
  // RPRC_13).
  function providerStatus(identifier, serviceIdentifier) {
    return certificateStatus(registrarStatuses.filter(s => s.identifier === identifier && !s.intendedUse && (s.service || '') === serviceIdentifier));
  }
  const entitlementLabel = (uri) => {
    const category = categories.find(c => c.entitlement === uri);
    return category ? category.label + ' provider' : '';
  };
  // kind is use for a verifier registration certificate and provider for an
  // issuer one.
  function statusBadge(kind, { status, reason }) {
    const subject = kind === 'use' ? 'intended use' : 'service';
    switch (status) {
      case 'none': return ['status-none ico-circle', 'No certificate', 'No registration certificate for this ' + subject + '.'];
      case 'active': return ['status-active ico-dot', 'Active', 'Not revoked.'];
      case 'revoked': return ['status-revoked ico-block', 'Revoked', 'Revoked on the registrar\'s status list.'];
      case 'expired': return ['status-revoked ico-block', 'Expired', 'Expired. Issue a new one.'];
    }
    const changed = {
      entitlements: 'Entitlements changed',
      attestations: 'Attestation types changed',
    }[reason] || 'Registered details changed';
    return ['status-revoked ico-block', 'Revoked', changed + '. Revoked for good. Issue a new one.'];
  }
  // Revoking or activating applies to a certificate that is still current.
  const revocable = (status) => status === 'active' || status === 'revoked';

  // The list re-renders after an action and replaces the clicked button. The
  // next render focuses the element with its ID, or the dialog title when the
  // action removed it.
  let registrarFocusID = null;
  async function registrarAction(button, action) {
    const error = document.getElementById(registrarDetail ? 'registrar-cert-error' : 'registrar-parties-error');
    error.textContent = '';
    button.disabled = true;
    try {
      await action();
      registrarFocusID = button.id;
      await loadRegistrarParties();
    } catch (e) {
      registrarFocusID = null;
      error.textContent = e.message;
      button.disabled = false;
      button.focus();
    }
  }

  function relyingPartySearchText(rp) {
    const parts = [rp.tradeName].concat((rp.legalPerson || {}).legalName || [], (rp.identifier || []).map(id => id.identifier));
    (rp.services || []).forEach(service => {
      parts.push(service.serviceTradeName);
      (service.providesAttestations || []).forEach(a => parts.push(registeredCredentialSummary(a)));
      (service.intendedUses || []).forEach(use => {
        (use.purpose || []).forEach(p => parts.push(p.content));
        (use.credentials || []).forEach(c => parts.push(registeredCredentialSummary(c)));
      });
    });
    return parts.filter(Boolean).join('\n').toLowerCase();
  }

  // The register holds at most a few hundred relying parties, so the dialog
  // loads them once and searches and pages them here. The TS05 search API has
  // no free-text parameter.
  const REGISTRAR_PAGE_SIZE = 10;
  let registrarPage = 0;
  const registrarSearch = document.getElementById('registrar-search');

  // The newest registrations come first. Each entry keeps its search text, so
  // typing does not rebuild it.
  let registrarEntries = [];
  function registrarEntriesInRole() {
    const filter = document.querySelector('input[name="registrar-filter"]:checked').value;
    return registrarEntries.filter(entry => filter === 'all' || relyingPartyRoles(entry.rp).includes(filter));
  }

  function renderRegistrarSuggestions() {
    const suggestions = new Set();
    registrarEntriesInRole().forEach(({ rp }) => {
      if (rp.tradeName) suggestions.add(rp.tradeName);
      (rp.identifier || []).forEach(id => suggestions.add(id.identifier));
    });
    const datalist = document.getElementById('registrar-search-suggestions');
    datalist.innerHTML = '';
    Array.from(suggestions).sort().forEach(value => datalist.appendChild(new Option(value, value)));
  }

  function providerRow(identifier, prefix, service) {
    const servicePrefix = prefix + '-service-' + domID(service.serviceIdentifier || 'default');
    const certStatus = providerStatus(identifier, service.serviceIdentifier || '');
    const status = certStatus.status;
    const issuerInfo = storedInfo(identifier, s => !s.intendedUse && (s.service || '') === (service.serviceIdentifier || ''), 'issuerInfo');
    const entitlements = (service.entitlements || []).map(entitlementLabel).filter(Boolean);
    const row = document.createElement('div');
    row.className = 'registrar-use';
    row.id = servicePrefix;
    row.dataset.status = status;
    const [badgeClass, badgeText, badgeTitle] = statusBadge('provider', certStatus);
    const badge = '<span class="status-badge ' + badgeClass + '" id="' + servicePrefix + '-status" title="' + escHtml(badgeTitle) + '">' + badgeText + '</span>';
    const actions = protectedParties.has(identifier) ? '' : '<span class="registrar-use-actions" id="' + servicePrefix + '-actions">' +
      '<button type="button" class="btn btn-sm" id="' + servicePrefix + '-issue" title="' +
        (status === 'active' ? 'Issues a new certificate and revokes the old one.' : 'Issues a registration certificate.') +
        '">' + (status === 'none' ? 'Issue certificate' : 'Issue new certificate') + '</button>' +
      (!revocable(status) ? '' : '<button type="button" class="btn btn-sm" id="' + servicePrefix + '-revoke" title="' +
        (status === 'revoked' ? 'Makes the certificate valid.' : 'Revokes the certificate on the status list.') +
        '">' + (status === 'revoked' ? 'Activate' : 'Revoke') + '</button>') +
      '<button type="button" class="btn btn-sm" id="' + servicePrefix + '-edit">Edit attestation types</button>' +
      '<button type="button" class="btn btn-danger btn-sm" id="' + servicePrefix + '-delete" title="Removes it from the registration and revokes it.">Delete</button>' +
    '</span>';
    row.innerHTML =
      '<div class="registrar-use-kind" id="' + servicePrefix + '-kind" title="Entitles the issuer to the attestation types below (ETSI TS 119 475). Published in issuer_info.">Issuer registration certificate</div>' +
      '<div class="registrar-use-head" id="' + servicePrefix + '-head">' +
        '<span class="registrar-use-purpose" id="' + servicePrefix + '-entitlement">' + escHtml(entitlements.join(', ') || 'Attestation provider') + '</span>' +
        actions +
      '</div>' +
      '<div class="cred-pills registrar-pills" id="' + servicePrefix + '-pills">' + badge + '</div>' +
      registeredCredentialList(service.providesAttestations || [], servicePrefix + '-attestations', servicePrefix + '-attestation') +
      (issuerInfo === undefined ? '' :
        '<div class="registrar-use-result" id="' + servicePrefix + '-result">' +
          '<div class="registrar-result-head" id="' + servicePrefix + '-result-head">' +
            '<label class="consent-purpose-label" id="' + servicePrefix + '-issuer-info-label" for="' + servicePrefix + '-issuer-info">issuer_info</label>' +
            '<button type="button" class="btn btn-sm" id="' + servicePrefix + '-copy">Copy</button>' +
          '</div>' +
          '<textarea class="form-input form-textarea" id="' + servicePrefix + '-issuer-info" readonly></textarea>' +
        '</div>');
    if (issuerInfo !== undefined) {
      const field = row.querySelector('textarea');
      field.value = issuerInfo;
      wireCopyButton(row.querySelector('#' + servicePrefix + '-copy'), field);
    }
    const editTypes = row.querySelector('#' + servicePrefix + '-edit');
    if (editTypes) editTypes.addEventListener('click', () => {
      const entry = registrarEntries.find(e => ((e.rp.identifier || [])[0] || {}).identifier === identifier);
      if (!entry) return;
      registrarDetail = null;
      registrarCertOverlay.classList.remove('active');
      openRegistrarDialog(entry.rp, true, 'issuer', service);
    });
    const removeService = row.querySelector('#' + servicePrefix + '-delete');
    if (removeService) removeService.addEventListener('click', () => removeRegistrationCertificate(removeService, { identifier: identifier, service: service.serviceIdentifier || '' }));
    const issue = row.querySelector('#' + servicePrefix + '-issue');
    if (issue) {
      issue.addEventListener('click', () => registrarAction(issue, async () => {
        await registrarRequest('POST', 'api/registrar/registration-certificates', {
          identifier: identifier,
          serviceIdentifier: service.serviceIdentifier || '',
        });
      }));
    }
    const toggle = row.querySelector('#' + servicePrefix + '-revoke');
    if (toggle) {
      toggle.addEventListener('click', () => registrarAction(toggle, () => registrarRequest('POST', 'api/registrar/registration-certificates/status', {
        identifier: identifier,
        serviceIdentifier: service.serviceIdentifier || '',
        revoked: status !== 'revoked',
      })));
    }
    return row;
  }

  // useRow shows one intended use with its certificate and actions.
  function useRow(identifier, prefix, service, use) {
    const usePrefix = prefix + '-use-' + domID(use.intendedUseIdentifier);
    const certStatus = intendedUseStatus(identifier, use.intendedUseIdentifier);
    const status = certStatus.status;
    const [badgeClass, badgeText, badgeTitle] = statusBadge('use', certStatus);
    const verifierInfo = storedInfo(identifier, s => s.intendedUse === use.intendedUseIdentifier, 'verifierInfo');
    const row = document.createElement('div');
    row.className = 'registrar-use';
    row.id = usePrefix;
    row.dataset.status = status;
    row.innerHTML =
      '<div class="registrar-use-kind" id="' + usePrefix + '-kind" title="Credentials and claims for one purpose (ETSI TS 119 475). Sent in verifier_info.">Verifier registration certificate</div>' +
      '<div class="registrar-use-head" id="' + usePrefix + '-head">' +
        '<span class="registrar-use-purpose" id="' + usePrefix + '-purpose">' + escHtml(((use.purpose || [])[0] || {}).content || use.intendedUseIdentifier) + '</span>' +
        (protectedParties.has(identifier) ? '' : '<span class="registrar-use-actions" id="' + usePrefix + '-actions">' +
          '<button type="button" class="btn btn-sm" id="' + usePrefix + '-issue" title="' +
            { none: 'Issues a registration certificate.',
              active: 'Issues a new certificate and revokes the old one.',
              revoked: 'Issues a new certificate.',
              outdated: 'Issues a certificate for the changed details.',
              expired: 'Issues a new certificate.' }[status] +
            '">' + (status === 'none' ? 'Issue certificate' : 'Issue new certificate') + '</button>' +
          (!revocable(status) ? '' : '<button type="button" class="btn btn-sm" id="' + usePrefix + '-revoke" title="' +
            (status === 'revoked' ? 'Makes the certificate valid.' : 'Revokes the certificate on the status list.') +
            '">' + (status === 'revoked' ? 'Activate' : 'Revoke') + '</button>') +
          '<button type="button" class="btn btn-danger btn-sm" id="' + usePrefix + '-delete" title="Removes the intended use from the registration and revokes its certificates.">Delete</button>' +
        '</span>') +
      '</div>' +
      '<div class="cred-pills registrar-pills" id="' + usePrefix + '-pills">' +
        '<span class="status-badge ' + badgeClass + '" id="' + usePrefix + '-status" title="' + escHtml(badgeTitle) + '">' + badgeText + '</span>' +
      '</div>' +
      registeredCredentialList(use.credentials || [], usePrefix + '-credentials', usePrefix + '-credential') +
      (verifierInfo === undefined ? '' :
        '<div class="registrar-use-result" id="' + usePrefix + '-result">' +
          '<div class="registrar-result-head" id="' + usePrefix + '-result-head">' +
            '<label class="consent-purpose-label" id="' + usePrefix + '-verifier-info-label" for="' + usePrefix + '-verifier-info">verifier_info</label>' +
            '<button type="button" class="btn btn-sm" id="' + usePrefix + '-copy">Copy</button>' +
          '</div>' +
          '<textarea class="form-input form-textarea" id="' + usePrefix + '-verifier-info" readonly></textarea>' +
        '</div>');
    if (verifierInfo !== undefined) {
      const field = row.querySelector('textarea');
      field.value = verifierInfo;
      wireCopyButton(row.querySelector('#' + usePrefix + '-copy'), field);
    }
    const issue = row.querySelector('#' + usePrefix + '-issue');
    if (issue) issue.addEventListener('click', () => registrarAction(issue, async () => {
      await registrarRequest('POST', 'api/registrar/registration-certificates', {
        identifier: identifier,
        serviceIdentifier: service.serviceIdentifier || '',
        intendedUseIdentifier: use.intendedUseIdentifier,
      });
    }));
    const toggle = row.querySelector('#' + usePrefix + '-revoke');
    if (toggle) {
      toggle.addEventListener('click', () => registrarAction(toggle, () => registrarRequest('POST', 'api/registrar/registration-certificates/status', {
        identifier: identifier,
        intendedUseIdentifier: use.intendedUseIdentifier,
        revoked: status !== 'revoked',
      })));
    }
    const removeUse = row.querySelector('#' + usePrefix + '-delete');
    if (removeUse) removeUse.addEventListener('click', () => removeRegistrationCertificate(removeUse, { identifier: identifier, use: use.intendedUseIdentifier }));
    return row;
  }

  const registrarCertOverlay = document.getElementById('registrar-cert-overlay');
  let registrarDetail = null;
  const providerEntitlements = () => new Set(categories.map(c => c.entitlement).filter(Boolean));
  const withoutProviderEntitlements = (entitlements) => (entitlements || []).filter(e => !providerEntitlements().has(e));
  // Deleting a registration certificate removes what it certifies from the
  // registration: an intended use, or the attestation types of a service. The
  // registrar revokes the certificates of the removed content.
  function removeRegistrationCertificate(button, detail) {
    return registrarAction(button, async () => {
      const entry = registrarEntries.find(e => ((e.rp.identifier || [])[0] || {}).identifier === detail.identifier);
      if (!entry) return;
      const updated = JSON.parse(JSON.stringify(entry.rp));
      (updated.services || []).forEach(service => {
        if (detail.use) {
          service.intendedUses = (service.intendedUses || []).filter(u => u.intendedUseIdentifier !== detail.use);
        } else if ((service.serviceIdentifier || '') === detail.service) {
          service.providesAttestations = [];
          service.entitlements = withoutProviderEntitlements(service.entitlements);
        }
      });
      await registrarRequest('PUT', 'api/registrar/wrp', updated);
      if (registrarDetail) {
        registrarDetail = null;
        registrarCertOverlay.classList.remove('active');
        registrarPartiesOverlay.classList.add('active');
      }
      registrarFocusID = 'registrar-party-' + domID(detail.identifier) + '-add-use';
    });
  }

  function certSummary(rowPrefix, kind, title, badge, detail) {
    const [badgeClass, badgeText, badgeTitle] = badge;
    const line = document.createElement('div');
    line.className = 'registrar-cert-line';
    line.id = rowPrefix + '-summary';
    line.innerHTML =
      '<span class="registrar-use-kind" id="' + rowPrefix + '-summary-kind">' + kind + '</span>' +
      '<span class="registrar-cert-title" id="' + rowPrefix + '-summary-title">' + escHtml(title) + '</span>' +
      '<span class="status-badge ' + badgeClass + '" id="' + rowPrefix + '-summary-status" title="' + escHtml(badgeTitle) + '">' + badgeText + '</span>' +
      '<span class="registrar-cert-actions">' +
        '<button type="button" class="btn btn-sm" id="' + rowPrefix + '-details">Details</button>' +
        (protectedParties.has(detail.identifier) ? '' : '<button type="button" class="btn btn-danger btn-sm" id="' + rowPrefix + '-summary-delete" title="Removes it from the registration and revokes it.">Delete</button>') +
      '</span>';
    const removeButton = line.querySelector('#' + rowPrefix + '-summary-delete');
    if (removeButton) removeButton.addEventListener('click', () => removeRegistrationCertificate(removeButton, detail));
    line.querySelector('#' + rowPrefix + '-details').addEventListener('click', () => {
      registrarDetail = Object.assign({ opener: rowPrefix + '-details' }, detail);
      registrarPartiesOverlay.classList.remove('active');
      document.getElementById('registrar-cert-error').textContent = '';
      renderRegistrarDetail();
      registrarCertOverlay.classList.add('active');
      document.getElementById('registrar-cert-title').focus();
    });
    return line;
  }
  function renderRegistrarDetail() {
    if (!registrarDetail) return;
    const body = document.getElementById('registrar-cert-body');
    body.innerHTML = '';
    const entry = registrarEntries.find(e => ((e.rp.identifier || [])[0] || {}).identifier === registrarDetail.identifier);
    const rp = entry && entry.rp;
    const prefix = 'registrar-party-' + domID(registrarDetail.identifier);
    let row = null;
    (rp ? rp.services || [] : []).forEach(service => {
      if (registrarDetail.use) {
        const use = (service.intendedUses || []).find(u => u.intendedUseIdentifier === registrarDetail.use);
        if (use) row = useRow(registrarDetail.identifier, prefix, service, use);
      } else if ((service.serviceIdentifier || '') === registrarDetail.service && (service.providesAttestations || []).length > 0) {
        row = providerRow(registrarDetail.identifier, prefix, service);
      }
    });
    document.getElementById('registrar-cert-title').textContent = registrarDetail.use ? 'Verifier registration certificate' : 'Issuer registration certificate';
    document.getElementById('registrar-cert-party').textContent = rp ? (rp.tradeName || '') + ' · ' + registrarDetail.identifier : '';
    if (row) body.appendChild(row);
  }
  document.getElementById('registrar-cert-close').addEventListener('click', () => {
    const opener = registrarDetail && registrarDetail.opener;
    registrarDetail = null;
    registrarCertOverlay.classList.remove('active');
    registrarPartiesOverlay.classList.add('active');
    const button = opener && document.getElementById(opener);
    (button || document.querySelector('input[name="registrar-filter"]:checked')).focus();
  });

  function renderRegistrarParties() {
    const filter = document.querySelector('input[name="registrar-filter"]:checked').value;
    const query = registrarSearch.value.trim().toLowerCase();
    registrarPartyList.innerHTML = '';
    const inRole = registrarEntriesInRole();
    const matching = query ? inRole.filter(entry => entry.text.includes(query)) : inRole;
    const pages = Math.max(1, Math.ceil(matching.length / REGISTRAR_PAGE_SIZE));
    registrarPage = Math.min(registrarPage, pages - 1);
    const shown = matching.slice(registrarPage * REGISTRAR_PAGE_SIZE, (registrarPage + 1) * REGISTRAR_PAGE_SIZE);
    shown.forEach(({ rp }) => {
      const identifier = (rp.identifier || [])[0] ? rp.identifier[0].identifier : '';
      const prefix = 'registrar-party-' + domID(identifier);
      const locked = protectedParties.has(identifier);
      const card = document.createElement('div');
      card.className = 'registrar-party';
      card.id = prefix;
      card.dataset.identifier = identifier;
      card.innerHTML =
        '<div class="registrar-party-head" id="' + prefix + '-head">' +
          '<span class="registrar-party-name" id="' + prefix + '-name">' + escHtml(rp.tradeName || '') + '</span>' +
          (locked ? '' : '<span class="registrar-party-actions" id="' + prefix + '-actions">' +
            '<button type="button" class="btn btn-danger btn-sm" id="' + prefix + '-delete">Delete</button>' +
          '</span>') +
        '</div>' +
        '<div class="cred-pills registrar-pills" id="' + prefix + '-pills">' +
          relyingPartyRoles(rp).map(role =>
            '<span class="status-badge status-role-' + role + '" id="' + prefix + '-role-' + role + '">' +
            (role === 'verifier' ? 'Verifier' : 'Issuer') + '</span>').join('') +
          (locked ? '<span class="status-badge status-none" id="' + prefix + '-protected" title="Visitors of the public demo share this registration and can\'t change it.">' + LOCK_SVG + 'Protected</span>' : '') +
          '<code class="registrar-party-identifier" id="' + prefix + '-identifier">' + escHtml(identifier) + '</code>' +
        '</div>';
      // Both roles belong to one registration (CIR (EU) 2025/848 Annex I).
      const services = rp.services || [];
      services.filter(service => (service.providesAttestations || []).length > 0).forEach(service => {
        const entitlements = (service.entitlements || []).map(entitlementLabel).filter(Boolean);
        card.appendChild(certSummary(prefix + '-service-' + domID(service.serviceIdentifier || 'default'), 'Issuer registration certificate',
          entitlements.join(', ') || 'Attestation provider',
          statusBadge('provider', providerStatus(identifier, service.serviceIdentifier || '')),
          { identifier: identifier, service: service.serviceIdentifier || '' }));
      });
      services.forEach(service => {
        (service.intendedUses || []).forEach(use => {
          const usePrefix = prefix + '-use-' + domID(use.intendedUseIdentifier);
          card.appendChild(certSummary(usePrefix, 'Verifier registration certificate',
            ((use.purpose || [])[0] || {}).content || use.intendedUseIdentifier,
            statusBadge('use', intendedUseStatus(identifier, use.intendedUseIdentifier)),
            { identifier: identifier, use: use.intendedUseIdentifier }));
        });
      });
      const addRow = document.createElement('div');
      addRow.className = 'registrar-add-row';
      addRow.id = prefix + '-add';
      const addButton = (suffix, text, title, role) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-sm';
        button.id = prefix + suffix;
        button.title = title;
        button.textContent = text;
        button.addEventListener('click', () => {
          registrarPartiesOverlay.classList.remove('active');
          openRegistrarDialog(rp, true, role);
        });
        addRow.appendChild(button);
      };
      if (!locked) {
        addButton('-add-use', '+ Add verifier registration certificate',
          'Registers another purpose and issues its certificate.', 'verifier');
        if (!services.some(service => (service.providesAttestations || []).length > 0)) {
          addButton('-add-issuer', '+ Add issuer registration certificate',
            'Registers which attestation types this party may issue.', 'issuer');
        }
      }
      // Issuing an access certificate doesn't change the registration, so
      // protected parties offer it too.
      services.forEach(service => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-sm';
        button.id = prefix + '-service-' + domID(service.serviceIdentifier || 'default') + '-access';
        button.title = 'Signs an access certificate for your key.';
        button.textContent = services.length > 1 ? 'Issue access certificate for ' + serviceLabelOf(rp, service) : 'Issue access certificate';
        button.addEventListener('click', () => {
          registrarPartiesOverlay.classList.remove('active');
          openRegistrarDialog(rp, true, serviceRoles(service).includes('issuer') && !serviceRoles(service).includes('verifier') ? 'issuer' : 'verifier', null, service);
        });
        addRow.appendChild(button);
      });
      if (addRow.children.length > 0) card.appendChild(addRow);
      const remove = card.querySelector('#' + prefix + '-delete');
      if (remove) {
        remove.addEventListener('click', () =>
          registrarAction(remove, async () => {
            await registrarRequest('DELETE', 'api/registrar/wrp/' + encodeURIComponent(identifier));
          }));
      }
      registrarPartyList.appendChild(card);
    });
    const empty = document.getElementById('registrar-party-empty');
    empty.textContent = query
      ? 'No relying party matches "' + registrarSearch.value.trim() + '".'
      : { all: 'No relying parties yet.', verifier: 'No verifiers yet.', issuer: 'No issuers yet.' }[filter];
    empty.hidden = shown.length > 0;

    document.getElementById('registrar-pager').hidden = pages < 2;
    document.getElementById('registrar-page-info').textContent = 'Page ' + (registrarPage + 1) + ' of ' + pages +
      ' · ' + matching.length + (matching.length === 1 ? ' relying party' : ' relying parties');
    const prev = document.getElementById('registrar-page-prev');
    const next = document.getElementById('registrar-page-next');
    prev.disabled = registrarPage === 0;
    next.disabled = registrarPage >= pages - 1;
    // A disabled button loses the focus, so the other pager button takes it.
    if (document.activeElement === prev && prev.disabled) next.focus();
    if (document.activeElement === next && next.disabled) prev.focus();
    renderRegistrarDetail();
    if (registrarFocusID) {
      (document.getElementById(registrarFocusID) || document.getElementById(registrarDetail ? 'registrar-cert-title' : 'registrar-parties-title')).focus();
      registrarFocusID = null;
    }
  }

  // Opening the list while an action reloads it starts two loads. Only the
  // latest one renders.
  let registrarLoad = 0;
  // The registrar caps the page size, so the list follows the cursor.
  async function registrarRecords() {
    const data = [];
    let cursor = '';
    do {
      const page = await registrarRequest('GET', 'api/registrar/wrp' + (cursor ? '?cursor=' + encodeURIComponent(cursor) : ''));
      data.push(...(page.data || []));
      cursor = (page.pagination && page.pagination.next_cursor) || '';
    } while (cursor);
    return { data: data };
  }

  async function loadRegistrarParties() {
    const error = document.getElementById('registrar-parties-error');
    const load = ++registrarLoad;
    try {
      const [records, statuses] = await Promise.all([
        registrarRecords(),
        registrarRequest('GET', 'api/registrar/registration-certificates'),
      ]);
      if (load !== registrarLoad) return;
      registrarEntries = (records.data || []).map(rp => ({ rp: rp, text: relyingPartySearchText(rp) })).reverse();
      registrarStatuses = statuses || [];
    } catch (e) {
      // On an error the list keeps showing the previous result.
      if (load === registrarLoad) error.textContent = e.message;
      return;
    }
    renderRegistrarSuggestions();
    renderRegistrarParties();
  }

  document.querySelectorAll('input[name="registrar-filter"]').forEach(input => {
    input.addEventListener('change', () => {
      registrarPage = 0;
      renderRegistrarSuggestions();
      renderRegistrarParties();
    });
  });
  registrarSearch.addEventListener('input', () => {
    registrarPage = 0;
    renderRegistrarParties();
  });
  document.getElementById('registrar-page-prev').addEventListener('click', () => {
    registrarPage--;
    renderRegistrarParties();
  });
  document.getElementById('registrar-page-next').addEventListener('click', () => {
    registrarPage++;
    renderRegistrarParties();
  });
  // Closing a registrar dialog returns focus to the menu that opened it.
  // On a phone the menu is collapsed by then, so its toggle takes the focus.
  function focusRegistrarOpener() {
    const toggle = document.getElementById('registrar-menu-toggle');
    (toggle.offsetParent ? toggle : document.getElementById('header-menu-toggle')).focus();
  }
  function openRegistrarParties() {
    document.getElementById('registrar-parties-error').textContent = '';
    registrarPartiesOverlay.classList.add('active');
    document.querySelector('input[name="registrar-filter"]:checked').focus();
    loadRegistrarParties();
  }
  document.getElementById('registrar-parties-link').addEventListener('click', (event) => {
    event.preventDefault();
    registrarSearch.value = '';
    registrarPage = 0;
    openRegistrarParties();
  });
  document.getElementById('registrar-parties-close').addEventListener('click', () => {
    registrarPartiesOverlay.classList.remove('active');
    focusRegistrarOpener();
  });
  document.getElementById('registrar-parties-register').addEventListener('click', () => {
    registrarPartiesOverlay.classList.remove('active');
    openRegistrarDialog(null, true);
  });
  document.getElementById('registrar-parties-register-issuer').addEventListener('click', () => {
    registrarPartiesOverlay.classList.remove('active');
    openRegistrarDialog(null, true, 'issuer');
  });

  // The registrar dialogs are modal: Escape closes them and Tab stays inside.
  // Escape presses closeButton. For a dialog that creates its buttons anew,
  // closeButton is a function that returns the current one.
  function makeModal(overlay, closeButton) {
    const closer = typeof closeButton === 'function' ? closeButton : () => closeButton;
    overlay.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        const close = closer();
        if (!close) return;
        event.preventDefault();
        close.click();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = Array.from(overlay.querySelectorAll('button, input, select, textarea, a[href], summary'))
        .filter(el => !el.disabled && el.offsetParent !== null && !(el.type === 'radio' && !el.checked));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
  }
  makeModal(registrarPartiesOverlay, document.getElementById('registrar-parties-close'));
  makeModal(document.getElementById('registrar-cert-overlay'), document.getElementById('registrar-cert-close'));
  makeModal(document.getElementById('registrar-overlay'), document.getElementById('registrar-close'));
  makeModal(trustOverlay, document.getElementById('trust-close'));
  makeModal(trustProviderOverlay, document.getElementById('trust-provider-cancel'));
  makeModal(trustExternalOverlay, document.getElementById('trust-external-cancel'));
  // Escape dismisses an error or a result. A consent request needs an explicit
  // answer.
  makeModal(consentOverlay, () => document.getElementById('error-dismiss') || document.getElementById('result-dismiss'));

  const registrarOverlay = document.getElementById('registrar-overlay');
  const registrarSubmit = document.getElementById('registrar-submit');
  // registrarTarget is the relying party that gets a new intended use, or null
  // when the dialog registers a new verifier.
  let registrarTarget = null;
  // registrarFromList is true when the dialog was opened from the relying
  // parties list, so Close returns there.
  let registrarFromList = false;
  // registrarMode is verifier or issuer. A verifier registers an intended use,
  // an issuer its attestation types.
  let registrarMode = 'verifier';
  function showRegistered(done) {
    registrarSubmit.classList.toggle('registrar-registered', done);
    if (registrarAccessService) {
      registrarSubmit.textContent = done ? '\u2713 Issued' : 'Issue access certificate';
    } else if (registrarEditService) {
      registrarSubmit.textContent = done ? '\u2713 Saved' : 'Save and issue certificate';
    } else if (registrarTarget) {
      registrarSubmit.textContent = done ? '\u2713 Added' : 'Add certificate';
    } else {
      registrarSubmit.textContent = done ? '\u2713 Registered' : (registrarMode === 'issuer' ? 'Register issuer' : 'Register verifier');
    }
    registrarSubmit.disabled = done;
  }
  // After an edit the form needs a new registration, so the old result is
  // hidden.
  function registrarFormEdited(event) {
    if (event.target.closest('#registrar-result')) return;
    event.target.removeAttribute('aria-invalid');
    showRegistered(false);
    document.getElementById('registrar-result').hidden = true;
  }
  const registrarForm = document.getElementById('registrar-form');
  registrarForm.addEventListener('input', registrarFormEdited);
  registrarForm.addEventListener('change', registrarFormEdited);
  registrarForm.addEventListener('click', (event) => {
    if (event.target.closest('#registrar-add-credential, #registrar-add-attestation, [data-field="remove"]')) registrarFormEdited(event);
  });

  function showRegistrarError(message, field) {
    const error = document.getElementById('registrar-error');
    error.textContent = message;
    if (field) {
      field.setAttribute('aria-invalid', 'true');
      field.focus({ preventScroll: true });
    }
    error.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  // Each mode has its own example values. They replace the other mode's
  // values only where those are still unchanged.
  const REGISTRAR_EXAMPLE_DNS = 'verifier.example';
  const REGISTRAR_DEFAULTS = {
    verifier: { 'registrar-name': 'Example Verifier', 'registrar-legal-name': 'Example Verifier B.V.', 'registrar-support-uri': 'https://verifier.example/support', 'registrar-service-id': 'checkout' },
    issuer: { 'registrar-name': 'Example University', 'registrar-legal-name': 'Example University', 'registrar-support-uri': 'https://university.example/support', 'registrar-service-id': 'diplomas' },
  };
  function applyRegistrarMode(mode) {
    if (mode !== registrarMode) {
      Object.entries(REGISTRAR_DEFAULTS[mode]).forEach(([id, value]) => {
        const field = document.getElementById(id);
        if (field.value === REGISTRAR_DEFAULTS[registrarMode][id]) field.value = value;
      });
    }
    registrarMode = mode;
    const issuer = mode === 'issuer';
    document.getElementById('registrar-party-section-label').textContent = issuer ? 'Issuer' : 'Relying party';
    document.getElementById('registrar-issuer-section').hidden = !issuer;
    document.getElementById('registrar-use-section').hidden = issuer;
    document.getElementById('registrar-dns-section').hidden = issuer;
    document.getElementById('registrar-client-ids-block').hidden = issuer;
    document.getElementById('registrar-verifier-info-block').hidden = issuer;
    document.getElementById('registrar-issuer-info-block').hidden = !issuer;
    document.getElementById('registrar-csr-command').textContent = issuer
      ? 'openssl ecparam -name prime256v1 -genkey -noout -out issuer.key\nopenssl req -new -key issuer.key -subj "/" -out issuer.csr'
      : 'openssl ecparam -name prime256v1 -genkey -noout -out verifier.key\nopenssl req -new -key verifier.key -subj "/" -out verifier.csr';
  }

  // editService is the issuer service whose attestation types the dialog
  // edits, or null when it adds something.
  let registrarEditService = null;
  // registrarAccessService is set when the dialog only issues an access
  // certificate for this service.
  let registrarAccessService = null;
  function openRegistrarDialog(target, fromList, mode, editService, accessService) {
    registrarTarget = target || null;
    registrarEditService = editService || null;
    registrarAccessService = accessService || null;
    registrarFromList = !!fromList;
    applyRegistrarMode(mode || 'verifier');
    showRegistered(false);
    loadCatalogSuggestions();
    registrarForm.querySelectorAll('[aria-invalid]').forEach(field => field.removeAttribute('aria-invalid'));
    const targetName = registrarTarget ? (registrarTarget.tradeName || registrarTarget.identifier[0].identifier) : '';
    const addsIssuer = !!registrarTarget && registrarMode === 'issuer';
    const targetIssues = !!registrarTarget && !addsIssuer && relyingPartyRoles(registrarTarget).includes('issuer');
    // Each open fills the purpose, credentials and attestation types again.
    // Values from an earlier open don't carry over.
    document.getElementById('registrar-purpose').value = !registrarTarget ? 'Age check before checkout' : targetIssues ? 'Identity check before issuance' : '';
    registrarCredentials.innerHTML = '';
    addRegistrarCredential(FORMATS.SDJWT, 'urn:eudi:pid:1', targetIssues ? 'given_name, family_name' : 'age_equal_or_over.18');
    registrarAttestations.innerHTML = '';
    const attestations = registrarEditService ? (registrarEditService.providesAttestations || []) : [{ format: FORMATS.SDJWT, type: 'urn:example:diploma:1' }];
    attestations.forEach(a => addRegistrarAttestation(a.format, a.type));
    document.getElementById('registrar-entitlement').value = '';
    const targetHint = document.getElementById('registrar-target-hint');
    targetHint.hidden = !registrarTarget;
    targetHint.textContent = registrarAccessService
      ? 'The certificate carries the identity of this registration. Sign your request objects or issuer metadata with its key.'
      : registrarEditService
      ? 'Issues a new certificate and revokes the old one.'
      : addsIssuer
      ? 'Lists the attestation types below. Publish it in issuer_info of the signed issuer metadata.'
      : targetIssues
      ? 'Lets the issuer ask for credentials, such as a PID, before it issues. Send it in verifier_info.'
      : 'Registers another purpose. Send its certificate in verifier_info.';
    document.getElementById('registrar-title').textContent = registrarAccessService
      ? 'Issue an access certificate for ' + serviceLabelOf(registrarTarget, registrarAccessService)
      : registrarEditService
      ? 'Edit the attestation types of ' + targetName
      : registrarTarget
      ? 'Add ' + (addsIssuer ? 'an issuer' : 'a verifier') + ' registration certificate to ' + targetName
      : (registrarMode === 'issuer' ? 'Register an issuer' : 'Register a verifier');
    document.getElementById('registrar-party-section').hidden = !!registrarTarget;
    const accessOnly = !!registrarAccessService;
    if (accessOnly) {
      document.getElementById('registrar-issuer-section').hidden = true;
      document.getElementById('registrar-use-section').hidden = true;
      document.getElementById('registrar-verifier-info-block').hidden = true;
      document.getElementById('registrar-issuer-info-block').hidden = true;
    }
    // The key and the host names belong to one party, so they never carry
    // over to the next dialog.
    document.getElementById('registrar-csr').value = '';
    document.getElementById('registrar-dns').value = accessOnly ? '' : REGISTRAR_EXAMPLE_DNS;
    document.getElementById('registrar-registration-validity-label').hidden = accessOnly;
    document.getElementById('registrar-registration-validity').hidden = accessOnly;
    fillTargetServices(addsIssuer ? 'issuer' : 'verifier');
    document.getElementById('registrar-error').textContent = '';
    document.getElementById('registrar-result').hidden = true;
    offerReissue([]);
    registrarOverlay.classList.add('active');
    if (accessOnly) {
      document.getElementById('registrar-csr').focus();
    } else if (addsIssuer) {
      (registrarAttestations.querySelector('[data-field="type"]') || registrarSubmit).focus();
    } else {
      document.getElementById(registrarTarget ? 'registrar-purpose' : 'registrar-name').focus();
    }
  }
  // Entitlements belong to a service (TS6 v1.2.2 row 12). A registration
  // certificate covers a service or one of its intended uses (ARF RPRC_09,
  // RPRC_13) and lists the entitlements of the service.
  // A service that gains the other role gets another entitlement, so the
  // registrar revokes the certificates of its current role. A new service
  // keeps them valid but needs its own access certificate.
  const registrarTargetService = document.getElementById('registrar-target-service');
  const NEW_SERVICE = 'new';
  let registrarAddedRole = 'verifier';
  function serviceLabel(service) {
    return serviceLabelOf(registrarTarget, service);
  }
  function serviceLabelOf(rp, service) {
    const name = service.serviceTradeName || rp.tradeName || 'Service';
    return service.serviceIdentifier ? name + ' (' + service.serviceIdentifier + ')' : name;
  }
  function fillTargetServices(role) {
    registrarAddedRole = role;
    const adding = !!registrarTarget && !registrarEditService && !registrarAccessService;
    document.getElementById('registrar-target-section').hidden = !adding;
    registrarTargetService.innerHTML = '';
    if (adding) {
      const services = registrarTarget.services || [];
      services.forEach((service, i) => registrarTargetService.appendChild(new Option(serviceLabel(service), String(i))));
      registrarTargetService.appendChild(new Option('A new service', NEW_SERVICE));
      // A service that has the role already keeps its entitlements. Otherwise
      // the first service is preselected. The access certificate identifies it.
      const same = services.findIndex(service => serviceRoles(service).includes(role));
      registrarTargetService.value = services.length === 0 ? NEW_SERVICE : String(Math.max(0, same));
    }
    document.getElementById('registrar-new-service-id').value = '';
    updateTargetService();
  }
  // revokedByTarget lists the certificates revoked by the added role. Each
  // entry is a registration certificate request that issues one again.
  function revokedByTarget() {
    const service = targetService();
    if (!service || serviceRoles(service).includes(registrarAddedRole)) return [];
    const identifier = registrarTarget.identifier[0].identifier;
    const serviceIdentifier = service.serviceIdentifier || '';
    const current = (matches) => registrarStatuses.some(s => s.identifier === identifier && !s.superseded && matches(s));
    if (registrarAddedRole === 'verifier') {
      return current(s => !s.intendedUse && (s.service || '') === serviceIdentifier)
        ? [{ identifier: identifier, serviceIdentifier: serviceIdentifier }] : [];
    }
    return (service.intendedUses || []).filter(use => current(s => s.intendedUse === use.intendedUseIdentifier))
      .map(use => ({ identifier: identifier, serviceIdentifier: serviceIdentifier, intendedUseIdentifier: use.intendedUseIdentifier }));
  }
  function targetService() {
    if (!registrarTarget || registrarEditService || registrarAccessService || registrarTargetService.value === NEW_SERVICE) return null;
    return (registrarTarget.services || [])[Number(registrarTargetService.value)] || null;
  }
  function updateTargetService() {
    const adding = !!registrarTarget && !registrarEditService && !registrarAccessService;
    const newService = adding && registrarTargetService.value === NEW_SERVICE;
    const issuesAccess = !registrarTarget || newService || !!registrarAccessService;
    document.getElementById('registrar-new-service-section').hidden = !newService;
    document.getElementById('registrar-access-section').hidden = !issuesAccess;
    document.getElementById('registrar-access-result').hidden = !issuesAccess;
    const notice = document.getElementById('registrar-revocation-notice');
    const revoked = adding ? revokedByTarget() : [];
    const service = targetService();
    if (newService) {
      notice.textContent = 'The new service gets its own access certificate.';
    } else if (revoked.length > 0 && registrarAddedRole === 'verifier') {
      notice.textContent = 'The service ' + serviceLabel(service) + ' gets the Service_Provider entitlement. ' +
        'The registrar revokes its issuer registration certificate.';
    } else if (revoked.length > 0) {
      notice.textContent = 'The service ' + serviceLabel(service) + ' gets a provider entitlement. ' +
        'The registrar revokes ' + (revoked.length === 1 ? 'the certificate of 1 intended use.' : 'the certificates of ' + revoked.length + ' intended uses.');
    }
    notice.hidden = !newService && revoked.length === 0;
  }
  registrarTargetService.addEventListener('change', updateTargetService);

  // After the registrar revoked the certificates of the other role, one click
  // issues them again for the changed service.
  let registrarReissue = [];
  function offerReissue(revoked) {
    registrarReissue = revoked;
    const block = document.getElementById('registrar-reissue-block');
    block.hidden = revoked.length === 0;
    if (revoked.length === 0) return;
    const provider = !revoked[0].intendedUseIdentifier;
    document.getElementById('registrar-reissue-hint').textContent = provider
      ? 'Issuer registration certificate revoked.'
      : (revoked.length === 1 ? 'Verifier registration certificate revoked.' : revoked.length + ' verifier registration certificates revoked.');
    const button = document.getElementById('registrar-reissue');
    button.disabled = false;
    button.textContent = provider ? 'Issue a new issuer registration certificate'
      : revoked.length === 1 ? 'Issue a new verifier registration certificate' : 'Issue new verifier registration certificates';
  }
  document.getElementById('registrar-reissue').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      for (const request of registrarReissue) {
        await registrarRequest('POST', 'api/registrar/registration-certificates',
          Object.assign({ validity: registrarValue('registrar-registration-validity') }, request));
      }
      button.textContent = '\u2713 Issued';
      document.getElementById('registrar-reissue-hint').textContent = 'New certificates issued.';
    } catch (e) {
      button.disabled = false;
      showRegistrarError(e.message);
    }
  });

  function showAccessResult(key, access) {
    document.getElementById('registrar-client-ids').innerHTML = (access.clientIds || []).map((id, i) =>
      '<li><code id="registrar-client-id-' + i + '">' + escHtml(id) + '</code></li>').join('');
    document.getElementById('registrar-pem-label').textContent = key ? 'Signing key and access certificate chain' : 'Access certificate chain';
    document.getElementById('registrar-pem').value = key + access.chain;
  }

  document.getElementById('registrar-close').addEventListener('click', () => {
    registrarOverlay.classList.remove('active');
    if (registrarFromList) {
      openRegistrarParties();
    } else {
      focusRegistrarOpener();
    }
  });

  // Each row is one credential type with its claims, as in the credentials of
  // an ETSI TS 119 475 registration certificate.
  let registrarCredentialCount = 0;
  const registrarCredentials = document.getElementById('registrar-credentials');
  // The type field suggests catalogue types in the row's format.
  function credentialPlaceholders(row) {
    const mdoc = row.querySelector('select').value === FORMATS.MDOC;
    const type = row.querySelector('[data-field="type"]');
    type.placeholder = mdoc ? 'doctype, e.g. eu.europa.ec.eudi.pid.1' : 'vct, e.g. urn:eudi:pid:1';
    type.setAttribute('list', mdoc ? 'registrar-types-mdoc' : 'registrar-types-sdjwt');
    const claims = row.querySelector('[data-field="claims"]');
    if (claims) {
      claims.placeholder = mdoc
        ? 'claims, e.g. given_name, eu.europa.ec.eudi.pid.de.1:birth_name'
        : 'claims, e.g. given_name, address.locality';
    }
  }
  function addRegistrarCredential(format, type, claims) {
    const n = ++registrarCredentialCount;
    const row = document.createElement('div');
    row.className = 'registrar-credential';
    row.id = 'registrar-credential-' + n;
    row.innerHTML =
      '<select class="form-input" data-field="format" id="registrar-credential-' + n + '-format" aria-label="Format">' +
        formatOptions([FORMATS.SDJWT, FORMATS.MDOC]) + '</select>' +
      '<input type="text" class="form-input" data-field="type" id="registrar-credential-' + n + '-type" aria-label="Credential type" autocomplete="off">' +
      '<input type="text" class="form-input" data-field="claims" id="registrar-credential-' + n + '-claims" aria-label="Claims, comma separated">' +
      '<button type="button" class="btn btn-sm" data-field="remove" id="registrar-credential-' + n + '-remove" aria-label="Remove this credential">Remove</button>';
    row.querySelector('select').value = format;
    row.querySelector('[data-field="type"]').value = type;
    row.querySelector('[data-field="claims"]').value = claims;
    row.querySelector('select').addEventListener('change', () => credentialPlaceholders(row));
    row.querySelector('button').addEventListener('click', () => row.remove());
    credentialPlaceholders(row);
    registrarCredentials.appendChild(row);
  }
  function firstCredentialTypeField() {
    const field = registrarCredentials.querySelector('[data-field="type"]');
    if (field) return field;
    addRegistrarCredential(FORMATS.SDJWT, '', '');
    return registrarCredentials.querySelector('[data-field="type"]');
  }
  document.getElementById('registrar-add-credential').addEventListener('click', () => {
    addRegistrarCredential(FORMATS.SDJWT, '', '');
    registrarCredentials.lastElementChild.querySelector('[data-field="type"]').focus();
  });

  // Each attestation type of an issuer is a format and a type
  // (ETSI TS 119 475 V1.2.1 Table 8).
  let registrarAttestationCount = 0;
  const registrarAttestations = document.getElementById('registrar-attestations');
  function addRegistrarAttestation(format, type) {
    const n = ++registrarAttestationCount;
    const row = document.createElement('div');
    row.className = 'registrar-credential';
    row.id = 'registrar-attestation-' + n;
    row.innerHTML =
      '<select class="form-input" data-field="format" id="registrar-attestation-' + n + '-format" aria-label="Format">' +
        formatOptions([FORMATS.SDJWT, FORMATS.MDOC]) + '</select>' +
      '<input type="text" class="form-input" data-field="type" id="registrar-attestation-' + n + '-type" aria-label="Attestation type" autocomplete="off">' +
      '<button type="button" class="btn btn-sm" data-field="remove" id="registrar-attestation-' + n + '-remove" aria-label="Remove this attestation">Remove</button>';
    row.querySelector('select').value = format;
    row.querySelector('[data-field="type"]').value = type;
    row.querySelector('select').addEventListener('change', () => credentialPlaceholders(row));
    row.querySelector('button').addEventListener('click', () => row.remove());
    credentialPlaceholders(row);
    registrarAttestations.appendChild(row);
  }
  document.getElementById('registrar-add-attestation').addEventListener('click', () => {
    addRegistrarAttestation(FORMATS.SDJWT, '');
    registrarAttestations.lastElementChild.querySelector('[data-field="type"]').focus();
  });
  function registrarAttestationList() {
    const attestations = [];
    registrarAttestations.querySelectorAll('.registrar-credential').forEach(row => {
      const format = row.querySelector('select').value;
      const type = row.querySelector('[data-field="type"]').value.trim();
      if (!type) return;
      attestations.push({ format: format, type: type });
    });
    return attestations;
  }

  // For mdoc, a claim is the element name in the doctype's namespace, or
  // namespace:element for another namespace.
  function registrarCredentialList() {
    const credentials = [];
    registrarCredentials.querySelectorAll('.registrar-credential').forEach(row => {
      const format = row.querySelector('select').value;
      const type = row.querySelector('[data-field="type"]').value.trim();
      if (!type) return;
      const claims = row.querySelector('[data-field="claims"]').value.split(',').map(c => c.trim()).filter(Boolean).map(claim => {
        if (format !== FORMATS.MDOC) return { path: window.eudiParseClaimPath(claim) };
        const at = claim.lastIndexOf(':');
        return { path: at > 0 ? [claim.slice(0, at), claim.slice(at + 1)] : [type, claim] };
      });
      credentials.push({
        format: format,
        meta: format === FORMATS.MDOC ? { doctype_value: type } : { vct_values: [type] },
        claims: claims,
      });
    });
    return credentials;
  }

  // RegistrarProblem marks an unusable form value. field names the input to
  // focus.
  class RegistrarProblem extends Error {
    constructor(message, field) {
      super(message);
      this.field = field;
    }
  }

  function requireAttestations() {
    const attestations = registrarAttestationList();
    if (attestations.length === 0) throw new RegistrarProblem('Add at least one attestation.', 'attestation');
    return attestations;
  }

  // accessCertificateRequest asks for the access certificate of a service. An
  // empty csr makes the submit create a key in the browser.
  function accessCertificateRequest(serviceIdentifier, withDNSNames) {
    const access = { serviceIdentifier: serviceIdentifier, csr: registrarValue('registrar-csr'), validity: registrarValue('registrar-access-validity') };
    if (withDNSNames) access.dnsNames = registrarValue('registrar-dns').split(',').map(n => n.trim()).filter(Boolean);
    return access;
  }

  // registrarPlan builds the registrar dialog's request: method, path and body.
  // access is the access certificate request inside the body. It throws a
  // RegistrarProblem for an unusable form value.
  function registrarPlan() {
    if (registrarAccessService) {
      const body = Object.assign({ identifier: registrarTarget.identifier[0].identifier },
        accessCertificateRequest(registrarAccessService.serviceIdentifier || '', registrarAddedRole === 'verifier'));
      return { kind: 'access', method: 'POST', path: 'api/registrar/access-certificates', body: body, access: body };
    }
    // Each registration certificate covers one intended use, so a new
    // certificate needs a new intended use. A verifier can also issue. In that
    // case its service gets the attestation types.
    if (registrarTarget) {
      const issuer = registrarMode === 'issuer';
      const use = issuer ? null : intendedUseFromForm();
      if (use && use.purpose.length === 0) throw new RegistrarProblem('The intended use needs a purpose.', 'registrar-purpose');
      if (use && use.credentials.length === 0) throw new RegistrarProblem('Add at least one credential.', 'credential');
      const attestations = issuer ? requireAttestations() : null;
      const target = registrationTarget();
      const service = target.service;
      if (issuer) {
        service.providesAttestations = attestations;
        // Without provider entitlements the registrar derives them from the
        // categories of the types, so changed types get matching entitlements.
        if (registrarEditService) service.entitlements = withoutProviderEntitlements(service.entitlements);
        const entitlement = document.getElementById('registrar-entitlement').value;
        if (entitlement) service.entitlements = (service.entitlements || []).concat([entitlement]);
      } else {
        service.intendedUses = (service.intendedUses || []).concat([use]);
      }
      const access = target.added ? accessCertificateRequest(service.serviceIdentifier, registrarAddedRole === 'verifier') : undefined;
      const registration = { serviceIdentifier: service.serviceIdentifier || '', validity: registrarValue('registrar-registration-validity') };
      if (issuer) registration.provider = true;
      return {
        kind: 'add', identifier: target.identifier, method: 'PUT', path: 'api/registrar/enrolments',
        body: { relyingParty: target.updated, access: access, registration: registration }, access: access,
      };
    }
    // An issuer gets its access certificate and one registration certificate
    // for its service (ARF RPRC_13). The issuer_info value carries the
    // registration certificate in the issuer metadata (ETSI TS 119 472-3 V1.1.1
    // §4.2.3).
    const issuer = registrarMode === 'issuer';
    if (!registrarValue('registrar-name')) throw new RegistrarProblem(issuer ? 'The issuer needs a name.' : 'The relying party needs a name.', 'registrar-name');
    const serviceIdentifier = registrarValue('registrar-service-id');
    const identifier = registrarValue('registrar-identifier');
    const service = {
      serviceTradeName: registrarValue('registrar-name'),
      serviceIdentifier: serviceIdentifier,
      supportURI: registrarValue('registrar-support-uri'),
    };
    if (issuer) {
      service.entitlements = document.getElementById('registrar-entitlement').value ? [document.getElementById('registrar-entitlement').value] : [];
      service.providesAttestations = requireAttestations();
    } else {
      const use = intendedUseFromForm();
      if (use.purpose.length === 0) throw new RegistrarProblem('The intended use needs a purpose.', 'registrar-purpose');
      if (use.credentials.length === 0) throw new RegistrarProblem('Add at least one credential.', 'credential');
      service.intendedUses = [use];
    }
    const access = accessCertificateRequest(serviceIdentifier, !issuer);
    const registration = { serviceIdentifier: serviceIdentifier, validity: registrarValue('registrar-registration-validity') };
    if (issuer) registration.provider = true;
    return {
      kind: 'register', method: 'POST', path: 'api/registrar/enrolments', access: access,
      body: {
        relyingParty: {
          identifier: identifier ? [{ identifier: identifier }] : [],
          legalPerson: { legalName: registrarValue('registrar-legal-name') ? [registrarValue('registrar-legal-name')] : [] },
          country: registrarValue('registrar-country'),
          tradeName: registrarValue('registrar-name'),
          services: [service],
        },
        access: access,
        registration: registration,
      },
    };
  }

  // problemField finds the input for a RegistrarProblem. Without an
  // attestation row, it adds one to focus.
  function problemField(field) {
    if (field === 'credential') return firstCredentialTypeField();
    if (field === 'attestation') {
      if (!registrarAttestations.querySelector('[data-field="type"]')) addRegistrarAttestation(FORMATS.SDJWT, '');
      return registrarAttestations.querySelector('[data-field="type"]');
    }
    return field ? document.getElementById(field) : undefined;
  }

  // Registering issues both certificates in one step. If a certificate fails,
  // the registration is deleted again, so a retry starts clean. A key created
  // in the browser is shown with the chain, because it exists nowhere else.
  document.getElementById('registrar-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = document.getElementById('registrar-submit');
    document.getElementById('registrar-error').textContent = '';
    let plan;
    try {
      plan = registrarPlan();
    } catch (e) {
      if (!(e instanceof RegistrarProblem)) throw e;
      showRegistrarError(e.message, problemField(e.field));
      return;
    }
    const revoked = plan.kind === 'add' ? revokedByTarget() : [];
    submit.disabled = true;
    try {
      let key = '';
      if (plan.access && !plan.access.csr) ({ key, csr: plan.access.csr } = await window.eudiCreateKeyAndCSR());
      showRegistrarResponse(plan, await registrarRequest(plan.method, plan.path, plan.body), key, revoked);
    } catch (e) {
      showRegistrarError(e.message);
    } finally {
      submit.disabled = submit.classList.contains('registrar-registered');
      // The disabled button dropped the focus while the request ran.
      if (!submit.disabled && document.activeElement === document.body) submit.focus();
    }
  });

  const CSR_PLACEHOLDER = '<your certificate signing request in PEM>';
  const CSR_NOTE = 'The dialog creates a key in the browser when the CSR field is empty. For the command, create a key and a CSR, for example with openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out csr.pem -subj "/CN=example". Then replace the placeholder with the CSR.';

  // registrarCommand is the API and CLI command for the registrar dialog.
  function registrarCommand() {
    const plan = registrarPlan();
    const body = JSON.parse(JSON.stringify(plan.body));
    const access = plan.kind === 'access' ? body : body.access;
    const needsCSR = Boolean(access && !access.csr);
    if (needsCSR) access.csr = CSR_PLACEHOLDER;
    const command = {
      curl: eudiDialogs.curl(plan.method, plan.path, body, { Accept: 'application/json' }),
      note: needsCSR ? CSR_NOTE : '',
    };
    if (plan.kind === 'access') {
      const flags = [['--identifier', body.identifier], ['--service-id', body.serviceIdentifier], ['--csr', needsCSR ? 'csr.pem' : '-']];
      for (const name of body.dnsNames || []) flags.push(['--dns', name]);
      if (body.validity) flags.push(['--validity', body.validity]);
      flags.push(['--remote', eudiDialogs.remoteURL()]);
      command.cli = eudiDialogs.cli('eudi registrar access-cert', flags) + (needsCSR ? '' : eudiDialogs.heredoc(body.csr));
    } else {
      const flags = plan.method === 'PUT' ? [['--update']] : [];
      flags.push(['--remote', eudiDialogs.remoteURL()]);
      command.cli = eudiDialogs.cli('eudi registrar enrol -', flags) + eudiDialogs.heredoc(JSON.stringify(body, null, 2));
    }
    command.cliNote = command.note;
    command.docs = {
      text: 'This enrolment is an eudi-dev endpoint. It registers the party and issues both certificates in one step. For the standardized TS05 registry endpoints, see',
      label: 'Registrar API',
      href: docsURL('docs/wallet/registrar.md#registrar-api'),
    };
    return command;
  }
  eudiDialogs.setCommand(document.getElementById('registrar-dialog'), registrarCommand);

  function showRegistrarResponse(plan, result, key, revoked) {
    if (plan.kind === 'access') {
      document.getElementById('registrar-result-identifier').textContent = plan.body.identifier;
      showAccessResult(key, result);
      showRegistrationResult();
      return;
    }
    if (plan.kind === 'add') registrarTarget = result.relyingParty;
    document.getElementById('registrar-result-identifier').textContent = plan.identifier || result.relyingParty.identifier[0].identifier;
    if (result.access) showAccessResult(key, result.access);
    if (registrarMode === 'issuer') document.getElementById('registrar-issuer-info').value = result.registration.issuerInfo;
    else document.getElementById('registrar-verifier-info').value = result.registration.verifierInfo;
    if (plan.kind === 'add') offerReissue(revoked);
    showRegistrationResult();
  }

  // The dialog scrolls to its end, so the result and the confirmed submit
  // button below it are both in view.
  function showRegistrationResult() {
    showRegistered(true);
    const box = document.getElementById('registrar-result');
    box.hidden = false;
    box.focus({ preventScroll: true });
    const dialog = document.getElementById('registrar-dialog');
    dialog.scrollTo({ top: dialog.scrollHeight, behavior: 'smooth' });
  }

  function intendedUseFromForm() {
    const privacyPolicy = registrarValue('registrar-privacy-policy');
    return {
      purpose: registrarValue('registrar-purpose') ? [{ lang: 'en', content: registrarValue('registrar-purpose') }] : [],
      privacyPolicy: privacyPolicy ? [{ policyURI: privacyPolicy }] : [],
      credentials: registrarCredentialList(),
    };
  }

  // registrationTarget copies the registration with the service that gets
  // the addition: the edited service, the chosen one, or a new one. added is
  // true for a new service. It throws a RegistrarProblem for a new service
  // without an identifier.
  function registrationTarget() {
    const identifier = registrarTarget.identifier[0].identifier;
    const updated = JSON.parse(JSON.stringify(registrarTarget));
    updated.services = updated.services || [];
    if (registrarEditService) {
      const index = updated.services.findIndex(s => (s.serviceIdentifier || '') === (registrarEditService.serviceIdentifier || ''));
      return { identifier, updated, service: updated.services[Math.max(0, index)], added: false };
    }
    if (registrarTargetService.value !== NEW_SERVICE) {
      return { identifier, updated, service: updated.services[Number(registrarTargetService.value)], added: false };
    }
    const field = document.getElementById('registrar-new-service-id');
    const serviceIdentifier = field.value.trim();
    if (!serviceIdentifier && updated.services.length > 0) throw new RegistrarProblem('The new service needs an identifier.', 'registrar-new-service-id');
    const service = { serviceTradeName: registrarTarget.tradeName, serviceIdentifier: serviceIdentifier };
    updated.services.push(service);
    return { identifier, updated, service, added: true };
  }

  document.getElementById('registrar-download-pem').addEventListener('click', () => {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([document.getElementById('registrar-pem').value], { type: 'application/x-pem-file' }));
    link.download = registrarMode === 'issuer' ? 'issuer.pem' : 'verifier.pem';
    link.click();
    // Some browsers start the download after click() returns.
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });

  [
    ['registrar-copy-pem', 'registrar-pem'],
    ['registrar-copy-verifier-info', 'registrar-verifier-info'],
    ['registrar-copy-issuer-info', 'registrar-issuer-info'],
    ['registrar-copy-csr-command', 'registrar-csr-command'],
  ].forEach(([buttonId, fieldId]) => wireCopyButton(document.getElementById(buttonId), document.getElementById(fieldId)));

  // The attestation catalogue (EC TS11 v1.0). Its entries fill the type
  // suggestions of the registration dialogs.
  let catalogEntries = [];
  async function loadCatalogEntries() {
    catalogEntries = await registrarRequest('GET', 'api/catalog/attestations');
    const lists = { [FORMATS.SDJWT]: 'registrar-types-sdjwt', [FORMATS.MDOC]: 'registrar-types-mdoc' };
    Object.values(lists).forEach(id => { document.getElementById(id).innerHTML = ''; });
    const seen = new Set();
    catalogEntries.forEach(entry => (entry.credentials || []).forEach(c => {
      const key = c.format + ' ' + c.type;
      if (!lists[c.format] || seen.has(key)) return;
      seen.add(key);
      const option = new Option(entry.name, c.type);
      option.value = c.type;
      option.label = entry.name;
      document.getElementById(lists[c.format]).appendChild(option);
    }));
  }
  function loadCatalogSuggestions() {
    loadCatalogEntries().catch(() => { /* The fields work without suggestions. */ });
  }

  const catalogOverlay = document.getElementById('registrar-catalog-overlay');
  const catalogList = document.getElementById('registrar-catalog-list');
  const catalogSearch = document.getElementById('registrar-catalog-search');
  const catalogLink = (href, text, id) => isWebURL(href)
    ? '<a href="' + escHtml(href) + '" target="_blank" rel="noopener" id="' + id + '">' + escHtml(text) + ' \u2197</a>'
    : '<span id="' + id + '">' + escHtml(text) + '</span>';

  // The filters combine: an entry matches when it has one of the selected
  // values in every group that has a selection.
  const catalogFilters = { category: new Set(), los: new Set(), binding: new Set(), source: new Set() };
  const catalogFilterValue = {
    category: entry => entry.category,
    los: entry => (entry.schema || {}).attestationLoS,
    binding: entry => (entry.schema || {}).bindingType,
    source: entry => entry.template ? 'template' : entry.operator ? 'operator' : 'added',
  };
  function renderCatalogFilters() {
    const box = document.getElementById('registrar-catalog-filters');
    const groups = [
      ['category', 'Category', categories.map(c => [c.id, c.label])],
      ['los', 'Level of security', schemaOptions.attestationLoS.map(o => [o.value, o.label])],
      ['binding', 'Holder binding', schemaOptions.bindingType.map(o => [o.value, o.label])],
      ['source', 'Source', [['template', 'From a template'], ['operator', 'Pre-registered'], ['added', 'Added here']]],
    ];
    box.innerHTML = '';
    groups.forEach(([group, label, options]) => {
      const shown = options;
      const row = document.createElement('div');
      row.className = 'catalog-filter-row';
      row.id = 'registrar-catalog-filter-' + group;
      row.innerHTML = '<span class="catalog-filter-label" id="' + row.id + '-label">' + label + '</span>';
      shown.forEach(([value, text]) => {
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'filter-chip';
        chip.id = 'registrar-catalog-filter-' + group + '-' + domID(value);
        chip.textContent = text;
        chip.setAttribute('aria-pressed', String(catalogFilters[group].has(value)));
        chip.addEventListener('click', () => {
          if (!catalogFilters[group].delete(value)) catalogFilters[group].add(value);
          renderCatalog();
          document.getElementById(chip.id).focus();
        });
        row.appendChild(chip);
      });
      box.appendChild(row);
    });
    if (Object.values(catalogFilters).some(set => set.size > 0)) {
      const clear = document.createElement('button');
      clear.type = 'button';
      clear.className = 'btn btn-sm catalog-filter-clear';
      clear.id = 'registrar-catalog-filter-clear';
      clear.textContent = 'Clear filters';
      clear.addEventListener('click', () => {
        Object.values(catalogFilters).forEach(set => set.clear());
        renderCatalog();
        catalogSearch.focus();
      });
      box.appendChild(clear);
    }
  }

  function renderCatalog() {
    renderCatalogFilters();
    const query = catalogSearch.value.trim().toLowerCase();
    const matching = catalogEntries.filter(entry => (!query ||
      [entry.name].concat((entry.credentials || []).map(c => c.type)).join('\n').toLowerCase().includes(query)) &&
      Object.entries(catalogFilters).every(([group, set]) => set.size === 0 || set.has(catalogFilterValue[group](entry))));
    catalogList.innerHTML = '';
    matching.forEach(entry => {
      const schema = entry.schema || {};
      const prefix = 'registrar-catalog-entry-' + domID(schema.id);
      const trust = (schema.trustedAuthorities || [])[0];
      const card = document.createElement('div');
      card.className = 'registrar-party';
      card.id = prefix;
      card.innerHTML =
        '<div class="registrar-party-head" id="' + prefix + '-head">' +
          '<span class="registrar-party-name" id="' + prefix + '-name">' + escHtml(entry.name) + '</span>' +
          ((entry.template || entry.operator) && demoMode ? '' : '<span class="registrar-party-actions"><button type="button" class="btn btn-danger btn-sm" id="' + prefix + '-delete">Delete</button></span>') +
        '</div>' +
        '<div class="cred-pills registrar-pills" id="' + prefix + '-pills">' +
          '<span class="status-badge catalog-badge" id="' + prefix + '-category" title="Selects the signer and the trusted list">Category: ' + escHtml(categoryLabel(entry.category)) + '</span>' +
          '<span class="status-badge catalog-badge" id="' + prefix + '-los" title="Level of security (TS11 attestationLoS)">Level of security: ' + escHtml(optionLabel('attestationLoS', schema.attestationLoS)) + '</span>' +
          '<span class="status-badge catalog-badge" id="' + prefix + '-binding" title="How the attestation is bound to its holder (TS11 bindingType)">' + escHtml(optionLabel('bindingType', schema.bindingType)) + '</span>' +
          (entry.template ? '<span class="status-badge catalog-badge" id="' + prefix + '-template" title="Change the credential template to change this entry.">From a template</span>' : '') +
          (entry.operator ? '<span class="status-badge catalog-badge" id="' + prefix + '-operator" title="The wallet loads this entry from its catalogue file on every start.">Pre-registered</span>' : '') +
          '<code class="registrar-party-identifier" id="' + prefix + '-id">' + escHtml(schema.id) + '</code>' +
          '<code class="registrar-party-identifier registrar-catalog-version" id="' + prefix + '-version">v' + escHtml(schema.version) + '</code>' +
        '</div>' +
        '<ul class="registrar-use-credentials" id="' + prefix + '-formats">' +
          (entry.credentials || []).map((c, i) => {
            const uri = ((schema.schemaURIs || []).find(u => u.formatIdentifier === c.format) || {}).uri;
            return '<li id="' + prefix + '-format-' + i + '">' + escHtml(c.format + ': ' + c.type) +
              (uri ? ' ' + catalogLink(uri, 'schema', prefix + '-schema-' + i) : '') + '</li>';
          }).join('') +
        '</ul>' +
        '<div class="registrar-catalog-links" id="' + prefix + '-links">' +
          catalogLink(schema.rulebookURI, 'Rulebook', prefix + '-rulebook') +
          (trust ? catalogLink(trust.value, 'Trusted list', prefix + '-trust') : '<span id="' + prefix + '-trust">No trusted list</span>') +
        '</div>';
      const remove = card.querySelector('#' + prefix + '-delete');
      if (remove) {
        remove.addEventListener('click', async () => {
          const error = document.getElementById('registrar-catalog-error');
          error.textContent = '';
          remove.disabled = true;
          try {
            await registrarRequest('DELETE', 'api/catalog/schemas/' + encodeURIComponent(schema.id));
            await loadCatalogEntries();
            renderCatalog();
            document.getElementById('registrar-catalog-title').focus();
          } catch (e) {
            error.textContent = e.message;
            remove.disabled = false;
          }
        });
      }
      catalogList.appendChild(card);
    });
    const empty = document.getElementById('registrar-catalog-empty');
    const filtered = Object.values(catalogFilters).some(set => set.size > 0);
    empty.textContent = query ? 'No attestation matches "' + catalogSearch.value.trim() + '".'
      : filtered ? 'No attestation matches the filters.' : 'The catalogue has no attestations yet.';
    empty.hidden = matching.length > 0;
  }

  async function openCatalog() {
    document.getElementById('registrar-catalog-error').textContent = '';
    catalogSearch.value = '';
    catalogOverlay.classList.add('active');
    catalogSearch.focus();
    try {
      await loadCatalogEntries();
    } catch (e) {
      document.getElementById('registrar-catalog-error').textContent = e.message;
    }
    renderCatalog();
  }
  document.getElementById('registrar-catalog-link').addEventListener('click', (event) => {
    event.preventDefault();
    openCatalog();
  });
  catalogSearch.addEventListener('input', renderCatalog);
  document.getElementById('registrar-catalog-close').addEventListener('click', () => {
    catalogOverlay.classList.remove('active');
    focusRegistrarOpener();
  });
  makeModal(catalogOverlay, document.getElementById('registrar-catalog-close'));

  const catalogForm = document.getElementById('registrar-catalog-form');
  linkCategoryLevel('registrar');
  function renderIssuerCAHint() {
    const category = categoryLabel(document.getElementById('registrar-catalog-category').value);
    document.getElementById('registrar-catalog-issuer-ca-hint').textContent =
      'Added as a provider on the ' + category + ' trusted list, so credentials of this issuer pass the trusted list check.';
  }
  document.getElementById('registrar-catalog-category').addEventListener('change', renderIssuerCAHint);
  const catalogAddOverlay = document.getElementById('registrar-catalog-add-overlay');
  // The dialog opens with an example filled in. Names are unique, so the
  // example name gets a number when the catalogue already has it.
  function resetCatalogForm() {
    const taken = new Set(catalogEntries.map(e => e.name.toLowerCase()));
    let name = 'University diploma';
    for (let n = 2; taken.has(name.toLowerCase()); n++) name = 'University diploma ' + n;
    document.getElementById('registrar-catalog-name').value = name;
    catalogFormats.innerHTML = '';
    addCatalogFormat(FORMATS.SDJWT, 'urn:example:diploma:1', 'degree, graduation_date');
    document.getElementById('registrar-catalog-category').value = 'eaa';
    document.getElementById('registrar-catalog-rulebook').value = '';
    document.getElementById('registrar-catalog-los').value = categoryLevel('eaa');
    document.getElementById('registrar-catalog-binding').value = defaultBinding();
    document.getElementById('registrar-catalog-trust').value = '';
    renderIssuerCAHint();
  }
  function openCatalogForm() {
    resetCatalogForm();
    document.getElementById('registrar-catalog-notice').hidden = true;
    document.getElementById('registrar-catalog-form-error').textContent = '';
    catalogForm.querySelectorAll('[aria-invalid]').forEach(field => field.removeAttribute('aria-invalid'));
    catalogOverlay.classList.remove('active');
    catalogAddOverlay.classList.add('active');
    document.getElementById('registrar-catalog-name').focus();
  }
  function closeCatalogForm() {
    catalogAddOverlay.classList.remove('active');
    catalogOverlay.classList.add('active');
  }
  let catalogFormatCount = 0;
  const catalogFormats = document.getElementById('registrar-catalog-formats');
  function addCatalogFormat(format, type, claims) {
    const n = ++catalogFormatCount;
    const row = document.createElement('div');
    row.className = 'registrar-credential';
    row.id = 'registrar-catalog-format-' + n;
    row.innerHTML =
      '<select class="form-input" data-field="format" id="registrar-catalog-format-' + n + '-format" aria-label="Format">' +
        formatOptions([FORMATS.SDJWT, FORMATS.MDOC]) + '</select>' +
      '<input type="text" class="form-input" data-field="type" id="registrar-catalog-format-' + n + '-type" aria-label="Type" autocomplete="off">' +
      '<input type="text" class="form-input" data-field="claims" id="registrar-catalog-format-' + n + '-claims" aria-label="Claims, comma separated">' +
      '<button type="button" class="btn btn-sm" data-field="remove" id="registrar-catalog-format-' + n + '-remove" aria-label="Remove this format">Remove</button>';
    row.querySelector('select').value = format;
    row.querySelector('[data-field="type"]').value = type;
    row.querySelector('[data-field="claims"]').value = claims;
    row.querySelector('select').addEventListener('change', () => credentialPlaceholders(row));
    row.querySelector('button').addEventListener('click', () => row.remove());
    credentialPlaceholders(row);
    // A new type is not in the catalogue yet, so this field suggests nothing.
    row.querySelector('[data-field="type"]').removeAttribute('list');
    catalogFormats.appendChild(row);
  }
  document.getElementById('registrar-catalog-add-format').addEventListener('click', () => {
    addCatalogFormat(FORMATS.MDOC, '', '');
    catalogFormats.lastElementChild.querySelector('[data-field="type"]').focus();
  });
  document.getElementById('registrar-catalog-add').addEventListener('click', openCatalogForm);
  document.getElementById('registrar-catalog-cancel').addEventListener('click', () => {
    closeCatalogForm();
    document.getElementById('registrar-catalog-add').focus();
  });
  makeModal(catalogAddOverlay, document.getElementById('registrar-catalog-cancel'));
  // catalogEntryRequest is the body of POST api/catalog/attestations for the
  // form's values. typed keeps each row's claims as typed, for the CLI.
  function catalogEntryRequest() {
    const credentials = [];
    const typed = [];
    catalogFormats.querySelectorAll('.registrar-credential').forEach(row => {
      const format = row.querySelector('select').value;
      const type = row.querySelector('[data-field="type"]').value.trim();
      if (!type) return;
      const names = row.querySelector('[data-field="claims"]').value.split(',').map(c => c.trim()).filter(Boolean);
      const claims = names.map(claim => {
        if (format !== FORMATS.MDOC) return window.eudiParseClaimPath(claim);
        const at = claim.lastIndexOf(':');
        return at > 0 ? [claim.slice(0, at), claim.slice(at + 1)] : [type, claim];
      });
      credentials.push({ format: format, type: type, claims: claims });
      typed.push({ format: format, type: type, claims: names });
    });
    const body = {
      name: document.getElementById('registrar-catalog-name').value.trim(),
      category: document.getElementById('registrar-catalog-category').value,
      credentials: credentials,
      schema: catalogSchema('registrar'),
    };
    const issuerCA = document.getElementById('registrar-catalog-issuer-ca').value.trim();
    if (issuerCA && body.schema.trustedAuthorities.length) {
      throw new Error("Use either an issuer CA or a trusted list. The issuer CA goes on the wallet's list of the category, and a trusted list links another list.");
    }
    return { body, typed, issuerCA };
  }

  // catalogCommand is the API and CLI command for adding the catalogue entry.
  // A pasted issuer CA goes on the category's trusted list in a second call.
  function catalogCommand() {
    const { body, typed, issuerCA } = catalogEntryRequest();
    const json = { Accept: 'application/json' };
    let curl = eudiDialogs.curl('POST', 'api/catalog/attestations', body, json);
    if (issuerCA) {
      curl += '\n\n' + eudiDialogs.curl('POST', 'api/trust/entities', { list: body.category, name: body.name + ' issuer', certificates: issuerCA }, json);
    }
    const flags = [['--name', body.name], ['--category', body.category]];
    for (const c of typed) {
      flags.push(['--type', c.format + ':' + c.type]);
      for (const claim of c.claims) flags.push(['--claim', c.format + ':' + claim]);
    }
    // --los takes the level without its iso_18045_ prefix.
    if (body.schema.attestationLoS) flags.push(['--los', body.schema.attestationLoS.replace(/^iso_18045_/, '')]);
    if (body.schema.bindingType) flags.push(['--binding', body.schema.bindingType]);
    if (body.schema.rulebookURI) flags.push(['--rulebook', body.schema.rulebookURI]);
    if (body.schema.trustedAuthorities.length) flags.push(['--trusted-list', body.schema.trustedAuthorities[0].value]);
    if (issuerCA) flags.push(['--issuer-ca', '-']);
    flags.push(['--remote', eudiDialogs.remoteURL()]);
    return {
      curl: curl,
      cli: eudiDialogs.cli('eudi catalog add', flags) + (issuerCA ? eudiDialogs.heredoc(issuerCA) : ''),
    };
  }
  eudiDialogs.setCommand(document.getElementById('registrar-catalog-add-dialog'), catalogCommand);

  catalogForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = document.getElementById('registrar-catalog-form-error');
    error.textContent = '';
    let body;
    try {
      ({ body } = catalogEntryRequest());
    } catch (e) {
      error.textContent = e.message;
      return;
    }
    const save = document.getElementById('registrar-catalog-save');
    save.disabled = true;
    try {
      const added = await registrarRequest('POST', 'api/catalog/attestations', body);
      const issuerCA = document.getElementById('registrar-catalog-issuer-ca');
      const notice = document.getElementById('registrar-catalog-notice');
      notice.hidden = true;
      if (issuerCA.value.trim()) {
        await registrarRequest('POST', 'api/trust/entities', { list: added.category, name: added.name + ' issuer', certificates: issuerCA.value });
        issuerCA.value = '';
        notice.textContent = 'Issuer CA added to the ' + categoryLabel(added.category) + ' trusted list. Remove it under Trust & certificates.';
        notice.hidden = false;
      }
      closeCatalogForm();
      await loadCatalogEntries();
      catalogSearch.value = '';
      renderCatalog();
      const card = document.getElementById('registrar-catalog-entry-' + domID(added.schema.id));
      if (card) {
        card.scrollIntoView({ block: 'nearest' });
        (card.querySelector('button') || document.getElementById('registrar-catalog-title')).focus();
      }
    } catch (e) {
      error.textContent = e.message;
    } finally {
      save.disabled = false;
      // The disabled button dropped the focus while the request ran.
      if (catalogAddOverlay.classList.contains('active') && document.activeElement === document.body) save.focus();
    }
  });

  const conformanceOverlay = document.getElementById('conformance-overlay');
  document.getElementById('conformance-link').addEventListener('click', (event) => {
    event.preventDefault();
    conformanceOverlay.classList.add('active');
  });
  document.getElementById('conformance-close').addEventListener('click', () => {
    conformanceOverlay.classList.remove('active');
  });

  const cliOverlay = document.getElementById('cli-overlay');
  document.getElementById('get-cli-link').addEventListener('click', (event) => {
    event.preventDefault();
    cliOverlay.classList.add('active');
  });
  document.getElementById('cli-close').addEventListener('click', () => {
    cliOverlay.classList.remove('active');
  });

  const howtoOverlay = document.getElementById('howto-overlay');
  document.getElementById('how-to-use-link').addEventListener('click', (event) => {
    event.preventDefault();
    document.querySelectorAll('.howto-origin').forEach((el) => {
      el.textContent = appBase.href.replace(/\/$/, '');
    });
    howtoOverlay.querySelectorAll('a[data-doc]').forEach((a) => {
      a.href = docsURL(a.dataset.doc);
    });
    howtoOverlay.classList.add('active');
  });
  const howtoTabs = Array.from(howtoOverlay.querySelectorAll('.howto-tab'));
  function selectHowtoTab(tab) {
    howtoTabs.forEach((t) => {
      const selected = t === tab;
      t.classList.toggle('active', selected);
      t.setAttribute('aria-selected', String(selected));
      t.tabIndex = selected ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !selected;
    });
  }
  howtoTabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectHowtoTab(tab));
    tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      const next = howtoTabs[(i + (event.key === 'ArrowRight' ? 1 : howtoTabs.length - 1)) % howtoTabs.length];
      selectHowtoTab(next);
      next.focus();
    });
  });
  document.getElementById('howto-close').addEventListener('click', () => {
    howtoOverlay.classList.remove('active');
  });

  // Remove consent identifiers from the address bar after reading them so copied links
  // cannot grant access.
  if (pageParams.get('focus') === 'overview' || openedForRequest || actingOwner) {
    if (pageParams.get('focus') === 'overview') {
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    }
    window.history.replaceState({}, document.title, window.location.pathname);
  }
  const loadAppConfigPromise = loadAppConfig();
  loadCredentials();
  loadDeferred();
  loadLog();
  // The pending requests load at once. A proxy can hold back the stream's
  // response, and the consent dialog must not wait for it.
  loadAppConfigPromise.then(loadPendingRequests);
  connectSSE();
})();
