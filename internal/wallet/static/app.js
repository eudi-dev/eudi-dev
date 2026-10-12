(function() {
  'use strict';

  const themeBtn = document.getElementById('theme-toggle');
  const saved = localStorage.getItem('wallet-theme');
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');
  themeBtn.addEventListener('click', () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    document.documentElement.setAttribute('data-theme', isLight ? '' : 'light');
    localStorage.setItem('wallet-theme', isLight ? '' : 'light');
  });

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

  const pageParams = new URLSearchParams(window.location.search);
  // Keep the consent owner in sessionStorage for reloads and remove it from shareable
  // URLs.
  const actingOwner = readActingOwner();
  // Read the request ID before clearing the address bar.
  const openedForRequest = pageParams.get('request') || '';

  // The request ID lets a browser without cookies answer the consent it was redirected to.
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
  let pendingRequests = [];
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
        const logoImg = display.logo_uri
          ? '<img class="credential-logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
          : '';
        const faceHtml = '<div class="card-face">' +
            '<span class="format-badge format-badge-face">' + formatLabel + '</span>' +
            logoImg +
            '<div class="face-name">' + escHtml(name) + '</div>' +
          '</div>';
        return '<div class="deferred-item" data-id="' + escHtml(p.id) + '">' +
          faceHtml +
          '<div class="deferred-body">' +
            '<div class="deferred-item-head">' +
              '<span class="format-badge format-badge-row">' + formatLabel + '</span>' +
              '<span class="deferred-name">' + escHtml(name) + '</span>' +
              '<span class="status-badge deferred-awaiting">Awaiting issuance</span>' +
            '</div>' +
            '<div class="deferred-meta deferred-status">' +
              '<span class="deferred-spinner" aria-hidden="true"></span>' +
              'The issuer asked the wallet to check back every ' + escHtml(p.interval || '') +
              (when ? '. Next attempt at ' + escHtml(when) : '') +
              (p.attempts ? ' (' + escHtml(p.attempts) + ' so far)' : '') +
            '</div>' +
            (p.issuer ? '<div class="deferred-meta">' + escHtml(p.issuer) + '</div>' : '') +
            (p.last_error ? '<div class="deferred-meta deferred-error">' + escHtml(p.last_error) + '</div>' : '') +
            '<div class="deferred-actions">' +
              '<button class="btn btn-sm deferred-check" data-id="' + escHtml(p.id) + '">Check now</button>' +
              '<button class="btn btn-sm btn-danger deferred-abandon" data-id="' + escHtml(p.id) + '">Abandon</button>' +
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
          btn.textContent = 'Checking...';
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
      // Issuance can create trust profiles, so refresh their links too.
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
  // including failed reads to avoid repeated requests.
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

  // Short IDs distinguish cards visually. API and CLI lookups use the full ID.
  function shortCredentialId(id) {
    return String(id || '').slice(0, 8);
  }

  function credentialInitials(name) {
    const words = String(name || '').replace(/[()]/g, ' ').split(/\s+/).filter(w => /^[a-z0-9]/i.test(w));
    return words.slice(0, 3).map(w => w[0]).join('').toUpperCase();
  }

  const GENERIC_FACE_GLYPH = '<span class="face-generic"><svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><rect x="3" y="5" width="18" height="14" rx="2.2"/><circle cx="8" cy="11" r="2"/><path d="M13 10h5M13 13h4M6 15.6h6"/></svg></span>';

  // An SVG lock inherits the text color. The emoji retains its own color.
  const LOCK_SVG = '<svg class="pill-ico" viewBox="0 0 24 24" width="11" height="11" fill="currentColor" aria-hidden="true"><path d="M12 1a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V6a5 5 0 0 0-5-5zm3 8H9V6a3 3 0 0 1 6 0v3z"/></svg>';

  function formatLabelFor(cred) {
    return cred.format === 'dc+sd-jwt' ? 'SD-JWT' : cred.format === 'jwt_vc_json' ? 'JWT VC' : 'mdoc';
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
      ? '<span class="status-badge status-protected" id="' + idPrefix + 'protected-' + cred.id + '"' +
        ' title="Part of this wallet\'s baseline. It cannot be deleted or revoked' +
        ' through the UI or the API, only by editing the wallet file.">' + LOCK_SVG + 'Protected</span>'
      : '';

    const st = cred.status;
    let statusBadge;
    if (st && st.managed) {
      const revoked = st.status === 1;
      dataset.status = revoked ? 'revoked' : 'active';
      statusBadge = '<span class="status-badge ' + (revoked ? 'status-revoked ico-block' : 'status-active ico-dot') + '" id="' + idPrefix + 'status-' + cred.id + '" title="' + (revoked ? 'The issuer has revoked this credential on its status list' : 'Not revoked on the issuer\'s status list') + ' (' + escHtml(st.uri || '') + ' idx ' + st.idx + ').">' + (revoked ? 'Revoked' : 'Active') + '</span>';
    } else if (st && st.uri) {
      dataset.status = 'external';
      statusBadge = '<span class="status-badge status-external ico-half" id="' + idPrefix + 'status-' + cred.id + '" title="Revocation is tracked on a status list this wallet does not manage, so its state is not read here (' + escHtml(st.uri) + ' idx ' + st.idx + ').">External list</span>';
    } else {
      statusBadge = '<span class="status-badge status-none ico-circle" id="' + idPrefix + 'status-' + cred.id + '" title="This credential carries no status list, so revocation cannot be checked.">No status</span>';
    }

    const expiry = expiryInfo(cred.expires_at);
    let expiryBadge = '';
    if (expiry) {
      dataset.expiry = expiry.state;
      expiryBadge = '<span class="status-badge status-' + expiry.state + ' ico-clock" id="' + idPrefix + 'expiry-' + cred.id +
        '" title="' + escHtml(expiry.title) + '">' + escHtml(expiry.label) + '</span>';
    }

    // An embedded key verifies signature consistency. It does not establish issuer trust
    // (ADR 0009).
    let signatureBadge = '';
    const sig = cred.signature;
    if (sig && sig.algorithm) {
      if (sig.self_consistent) {
        signatureBadge = '<span class="status-badge status-active ico-check" id="' + idPrefix + 'signature-' + cred.id +
          '" title="The signature verifies against the key material the credential carries (its x5c certificate or embedded jwk, ' + escHtml(sig.algorithm) +
          '). It is not checked against any trust anchor, so it proves the credential is intact, not who the issuer is.">Self-consistent</span>';
      } else {
        const kind = cred.issuer && cred.issuer.kind ? ' · ' + escHtml(cred.issuer.kind.toUpperCase()) : '';
        signatureBadge = '<span class="status-badge status-revoked ico-x" id="' + idPrefix + 'signature-' + cred.id +
          '" title="The credential carries no key material this wallet can verify the signature against offline, so its integrity is unchecked here.">not verified' + kind + '</span>';
      }
    }

    let keyBindingBadge = '';
    const binding = cred.holder_binding ||
      (cred.key_binding_not_held === true ? 'other_key' : '');
    if (binding === 'this_wallet') {
      dataset.keyBinding = 'this-wallet';
      keyBindingBadge = '<span class="status-badge status-active ico-check" id="' + idPrefix + 'key-binding-' + cred.id +
        '" title="Bound to a holder key this wallet holds, so it can be presented.">Bound to this wallet</span>';
    } else if (binding === 'other_key') {
      dataset.keyBinding = 'not-held';
      keyBindingBadge = '<span class="status-badge status-unheld-key ico-warn" id="' + idPrefix + 'key-binding-' + cred.id +
        '" title="Bound to a holder key this wallet does not hold. Presenting it fails the verifier\'s key binding check.">Bound to another key</span>';
    } else if (binding === 'none') {
      dataset.keyBinding = 'none';
      keyBindingBadge = '<span class="status-badge status-none" id="' + idPrefix + 'key-binding-' + cred.id +
        '" title="The credential names no holder key.">No key binding</span>';
    }

    const display = cred.display || {};
    const logoImg = display.logo_uri
      ? '<img class="credential-logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
      : '';
    const faceLabel = display.name ? escHtml(display.name) : escHtml(typeLabel);

    const faceHtml = '<div class="card-face">' +
      '<span class="format-badge format-badge-face">' + formatLabel + '</span>' +
      logoImg +
      '<div class="face-name">' + faceLabel + '</div>' +
      '</div>';

    const nameHtml = '<span class="credential-name">' + faceLabel + '</span>';


    const idMeta = '<span class="cred-meta-item cred-m-id"><span class="cred-meta-k">id</span> <span class="mono cred-shortid">#' + escHtml(shortCredentialId(cred.id)) + '</span></span>';

    const rel = relativeTime(cred.issued_at);
    const issuedMeta = rel ? '<span class="cred-meta-item cred-m-iat"><span class="cred-meta-k">iat</span> ' + escHtml(rel) + '</span>' : '';

    const typeMeta = display.name
      ? '<span class="cred-meta-item cred-m-type"><span class="cred-meta-k">type</span> <span class="mono">' + escHtml(typeLabel) + '</span></span>'
      : '';

    let issuerMeta = '';
    if (cred.issuer && cred.issuer.value) {
      issuerMeta = '<span class="cred-meta-item cred-m-iss"><span class="cred-meta-k">' + escHtml(cred.issuer.kind || 'iss') +
        '</span> <span class="mono">' + escHtml(cred.issuer.value) + '</span></span>';
    }

    const bodyHtml = '<div class="credential-info">' +
        '<div class="credential-type cred-hdr">' +
          '<span class="format-badge format-badge-row">' + formatLabel + '</span>' +
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
        const glyph = name && initials
          ? '<span class="face-init">' + escHtml(initials) + '</span>'
          : GENERIC_FACE_GLYPH;
        const nameEl = face.querySelector('.face-name');
        if (nameEl) nameEl.insertAdjacentHTML('beforebegin', glyph);
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
      card.id = 'credential-' + cred.id;
      Object.assign(card.dataset, body.dataset);

      const st = cred.status;
      let revokeBtn = '';
      if (st && st.managed) {
        if (!isProtected) {
          revokeBtn = '<button class="btn btn-sm" id="revoke-' + cred.id + '" data-revoke="' + cred.id + '">' + (st.status === 1 ? 'Activate' : 'Revoke') + '</button>';
        }
      } else if (st && st.uri) {
        revokeBtn = '<button class="btn btn-sm" id="status-check-' + cred.id + '" data-check-status="' + cred.id + '">Check status</button>';
      }

      // Container queries choose whether the description flips the card or expands beneath
      // it.
      const hasDesc = !!(cred.display && cred.display.description);
      const aboutBtn = hasDesc
        ? '<button class="btn btn-sm about-btn" id="about-' + cred.id + '" data-about="' + cred.id + '" aria-expanded="false" aria-label="Show description">' +
            descIcon('ic-info', '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 7.6h.01"/>') +
            '<span>About</span>' +
            descIcon('ic-chev', '<path d="M6 9l6 6 6-6"/>') +
          '</button>'
        : '';
      const actionsHtml = '<div class="credential-actions">' +
          aboutBtn +
          revokeBtn +
          '<button class="btn btn-sm" id="show-' + cred.id + '" data-show="' + cred.id + '">Show</button>' +
          (isProtected ? '' : '<button class="btn btn-danger btn-sm" id="delete-' + cred.id + '" data-delete="' + cred.id + '">Delete</button>') +
        '</div>';
      // The flipped card hides the About button, so phones need a Back control inside the
      // description.
      const descPane = hasDesc
        ? '<div class="cred-desc"><div class="cred-desc-in">' +
            '<div class="cred-desc-head"><span class="cred-desc-label">Description</span>' +
              '<button class="cred-desc-back" data-desc-close="' + cred.id + '" aria-label="Back to card">' +
                descIcon('', '<path d="M15 18l-6-6 6-6"/>') + '<span>Back</span></button></div>' +
            '<div class="cred-desc-body">' + linkifyText(cred.display.description) + '</div>' +
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
        revoke.addEventListener('click', () => setCredentialStatus(cred.id, st.status === 1 ? 0 : 1));
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

  function expiryInfo(value) {
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
        alert('Setting status failed: ' + (result.error || 'HTTP ' + resp.status));
        return;
      }
      await loadCredentials();
      await loadLog();
    } catch (e) {
      alert('Setting status failed: ' + e.message);
    }
  }

  async function checkCredentialStatus(id) {
    const badge = document.getElementById('status-' + id);
    if (badge) badge.textContent = 'Checking...';
    try {
      const resp = await fetch('api/credentials/' + id + '/status');
      const result = await resp.json();
      if (!badge) return;
      if (!resp.ok) {
        badge.textContent = 'Check failed';
        badge.title = result.error || ('HTTP ' + resp.status);
        return;
      }
      const revoked = result.status === 1;
      badge.textContent = revoked ? 'Revoked' : 'Active';
      badge.classList.remove('status-external');
      badge.classList.add(revoked ? 'status-revoked' : 'status-active');
      const card = document.getElementById('credential-' + id);
      if (card) card.dataset.status = revoked ? 'revoked' : 'active';
    } catch (e) {
      if (badge) {
        badge.textContent = 'Check failed';
        badge.title = e.message;
      }
    }
  }

  async function deleteCredential(id) {
    try {
      await fetch('api/credentials/' + id, { method: 'DELETE' });
      openDescriptions.delete(id);
      await loadCredentials();
      await loadLog();
    } catch (e) {
      console.error('Failed to delete credential:', e);
    }
  }

  processBtn.addEventListener('click', async () => {
    const uri = offerInput.value.trim();
    if (!uri) return;

    processBtn.disabled = true;
    processBtn.textContent = 'Processing...';

    try {
      const isVCI = uri.includes('credential_offer') ||
        uri.startsWith('openid-credential-offer://') ||
        uri.startsWith('haip-vci://') ||
        uri.startsWith('eu-eaa-offer://');
      const endpoint = isVCI ? 'api/offers' : 'api/presentations';
      expectError();

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uri: uri, interactive: true })
      });

      const result = await resp.json();
      if (followVerifierRedirect(result)) return;
      if (result.error) {
        alert('Error: ' + result.error);
      } else {
        offerInput.value = '';
        await loadCredentials();
        await loadLog();
      }
    } catch (e) {
      alert('Request failed: ' + e.message);
    } finally {
      processBtn.disabled = false;
      processBtn.textContent = 'Process';
    }
  });

  importBtn.addEventListener('click', () => {
    importOverlay.classList.add('active');
    importTextarea.value = '';
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
        const err = await resp.json();
        alert('Import failed: ' + (err.error || 'unknown error'));
        return;
      }
      importOverlay.classList.remove('active');
      await loadCredentials();
    } catch (e) {
      alert('Import failed: ' + e.message);
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
      '<label class="claim-sd" title="Allow selective disclosure. Uncheck to always disclose this claim."><input type="checkbox" id="issue-claim-sd-' + idx + '" checked> SD</label>' +
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
  function syncAlwaysDisclosedFromRows() {
    const nested = alwaysDisclosedList().filter(p => p.indexOf('.') !== -1);
    const plain = [];
    issueClaimRows.querySelectorAll('.claim-row').forEach(row => {
      const key = row.querySelector('input[id^="issue-claim-key-"]').value.trim();
      const sd = row.querySelector('input[id^="issue-claim-sd-"]').checked;
      if (key && !sd) plain.push(key);
    });
    issueAlwaysDisclosed.value = plain.concat(nested).join(', ');
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
      opt.textContent = t.name + (t.predefined ? ' (pre-defined)' : '');
      issueTemplateSelect.appendChild(opt);
    });
    issueTemplateSelect.value = current || '';
  }

  // Send the template name so the server can apply embedded images that the form cannot
  // carry.
  let issueDisplayTemplate = '';

  // Clear fields omitted by a new template to prevent values from mixing. Explicit form
  // values preserve user edits.
  function applyIssueTemplate(name) {
    const tpl = (templatesCache || []).find(t => t.name === name);
    if (!tpl) return;
    const display = tpl.display || {};
    issueDisplayTemplate = (display.logo || display.background_image) ? tpl.name : '';
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
    const note = document.getElementById('issue-template-art-note');
    if (note) note.hidden = !(display.logo || display.background_image);
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

  // Reset other fields when the format changes because their values may not apply.
  function resetIssueFields() {
    document.getElementById('issue-vct').value = '';
    document.getElementById('issue-doctype').value = '';
    document.getElementById('issue-exp').value = '';
    document.getElementById('issue-nbf').value = '';
    document.getElementById('issue-batch').value = '';
    document.getElementById('issue-binding').value = 'bound';
    document.getElementById('issue-save-template').value = '';
    document.getElementById('issue-status-list').value = 'auto';
    document.getElementById('issue-status-list-uri').value = '';
    document.getElementById('issue-status-list-uri').hidden = true;
    document.getElementById('issue-status-list-idx').value = '';
    document.getElementById('issue-status-list-idx').hidden = true;
    issueTemplateSelect.value = '';
    issueAlwaysDisclosed.value = '';
    issueDisplayTemplate = '';
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

  function bindImageUpload(fileId, textId) {
    document.getElementById(fileId).addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => { document.getElementById(textId).value = reader.result; };
      reader.onerror = () => { issueError.textContent = 'Could not read the selected file.'; };
      reader.readAsDataURL(file);
    });
  }
  bindImageUpload('issue-logo-file', 'issue-logo');
  bindImageUpload('issue-bg-image-file', 'issue-bg-image');

  issueForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    issueError.textContent = '';

    const body = { format: issueFormat.value };
    if (document.getElementById('issue-claims-mode-json').checked) {
      const claimsText = issueClaimsTextarea.value.trim();
      if (claimsText) {
        try {
          body.claims = JSON.parse(claimsText);
        } catch (e) {
          issueError.textContent = 'Claims must be valid JSON: ' + e.message;
          return;
        }
      }
    } else {
      syncAlwaysDisclosedFromRows();
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
    // presentation.
    const batch = parseInt(document.getElementById('issue-batch').value, 10);
    if (batch >= 2) body.batch = batch;
    if (document.getElementById('issue-binding').value === 'unbound') body.unbound = true;
    const statusListMode = document.getElementById('issue-status-list').value;
    if (statusListMode === 'none') {
      body.status_list_uri = '';
    } else if (statusListMode === 'custom') {
      body.status_list_uri = document.getElementById('issue-status-list-uri').value.trim();
      const idx = document.getElementById('issue-status-list-idx').value.trim();
      if (idx) body.status_list_idx = parseInt(idx, 10);
    }
    if (issueFormat.value === 'sdjwt') {
      const always = alwaysDisclosedList();
      if (always.length > 0) body.always_disclosed = always;
    }
    const saveTemplate = document.getElementById('issue-save-template').value.trim();
    if (saveTemplate) body.save_as_template = saveTemplate;
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
    if (Object.keys(display).length > 0) body.display = display;
    // The server applies template display values beneath fields explicitly supplied by the
    // form.
    if (issueDisplayTemplate) body.display_template = issueDisplayTemplate;

    issueSubmit.disabled = true;
    issueSubmit.textContent = 'Issuing...';
    try {
      const resp = await fetch('api/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const result = await resp.json();
      if (!resp.ok) {
        issueError.textContent = result.error || ('HTTP ' + resp.status);
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
  const templateForm = document.getElementById('template-form');
  const templateError = document.getElementById('template-error');
  const templateName = document.getElementById('template-name');
  const templateJSON = document.getElementById('template-json');

  function templateEditorFields(tpl) {
    const doc = Object.assign({}, tpl);
    delete doc.name;
    delete doc.predefined;
    return doc;
  }

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
      label.textContent = tpl.name;
      row.appendChild(label);

      const meta = document.createElement('span');
      meta.className = 'template-row-meta';
      meta.textContent = (tpl.format || 'any') + (tpl.predefined ? ' · pre-defined' : '');
      row.appendChild(meta);

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'btn btn-sm';
      editBtn.id = 'template-edit-' + tpl.name;
      editBtn.textContent = 'Edit';
      editBtn.addEventListener('click', () => {
        templateName.value = tpl.name;
        templateJSON.value = JSON.stringify(templateEditorFields(tpl), null, 2);
        templateError.textContent = '';
      });
      row.appendChild(editBtn);

      if (!tpl.predefined && !demoMode) {
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
              templateError.textContent = result.error || ('HTTP ' + resp.status);
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

  document.getElementById('templates-btn').addEventListener('click', () => {
    templateName.value = '';
    templateJSON.value = '';
    templateError.textContent = '';
    templatesOverlay.classList.add('active');
    renderTemplatesList();
  });

  document.getElementById('template-close').addEventListener('click', () => {
    templatesOverlay.classList.remove('active');
  });

  templateForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    templateError.textContent = '';
    let doc;
    try {
      doc = JSON.parse(templateJSON.value);
      if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
        throw new Error('expected a JSON object');
      }
    } catch (e) {
      templateError.textContent = 'Template must be valid JSON: ' + e.message;
      return;
    }
    const name = templateName.value.trim() || (typeof doc.name === 'string' ? doc.name.trim() : '');
    if (!name) {
      templateError.textContent = 'Template name is required';
      return;
    }
    try {
      const resp = await fetch('api/templates/' + encodeURIComponent(name), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(doc)
      });
      const result = await resp.json();
      if (!resp.ok) {
        templateError.textContent = result.error || ('HTTP ' + resp.status);
        return;
      }
      templateName.value = '';
      templateJSON.value = '';
      await renderTemplatesList();
    } catch (e) {
      templateError.textContent = 'Request failed: ' + e.message;
    }
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

    combineRequestLogs(log).reverse().forEach(entry => {
      const el = document.createElement('div');
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
      let html = '<div class="log-header" data-testid="log-entry-toggle">' +
        '<span class="log-chevron">' + (hasDetails ? '▸' : '') + '</span>' +
        '<span class="log-time">' + time + '</span>' +
        '<span class="log-action ' + entry.action + '">' + escHtml(entry.action) + '</span>' +
        '<span class="log-detail" title="' + escHtml(view.detail) + '">' + escHtml(view.detail) + '</span>' +
        '<span class="log-status ' + statusClass + '">' + statusLabel + '</span>' +
        '</div>';
      if (hasDetails) {
        html += '<div class="log-details">';
        if (Object.keys(view.details).length) html += renderLogDetails(view.details);
        if (view.payload) html += renderLogPayload(view.payload, view.decoderInput, view.presentations, view.credentials);
        else if (view.presentations.length) html += '<div class="log-payload-controls">' + renderLogPresentations(view.presentations) + '</div>';
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
    return { payload, detail, details, presentations, credentials, decoderInput };
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

  function renderLogPayload(payload, decoderInput, presentations, credentials) {
    const canToggle = payload.encrypted && payload.body != null && payload.wire !== undefined;
    const showWire = payload.encrypted && payload.wire !== undefined;
    let html = '<section class="log-payload"><div class="log-payload-heading"><div class="log-payload-label">' + escHtml(payload.label) + '</div>';
    if (payload.encrypted) {
      const view = showWire ? 'Encrypted view' : (payload.body != null ? 'Decrypted view' : 'Encrypted on wire');
      html += '<span class="log-payload-view" title="Encrypted on the wire">' + view + '</span>';
    }
    html += '</div>';
    let controls = '';
    if (canToggle) controls += '<button type="button" class="btn log-payload-toggle" data-testid="log-payload-toggle" title="Switch the log display between the wire value and plaintext">View decrypted</button>';
    if (decoderInput) controls += renderLogDecoderLink(decoderInput);
    if (presentations.length) controls += renderLogPresentations(presentations);
    for (const credential of credentials) {
      const label = credentials.length > 1 ? 'Open copy ' + (credential.index + 1) + ' in decoder' : 'Open in decoder';
      controls += renderLogDecoderLink(credential.token, label, {
        'credential-index': credential.index,
        ...(credential.id ? { 'credential-id': credential.id } : {}),
      });
    }
    if (controls) html += '<div class="log-payload-controls">' + controls + '</div>';
    const missing = payload.encrypted ? 'Plaintext unavailable' : 'No response body available';
    const value = showWire ? payload.wire : payload.body;
    const body = value == null ? missing : (value === '' ? '(empty body)' : logPayloadText(value));
    html += '<pre>' + escHtml(body) + '</pre>';
    if (payload.wire !== undefined && !payload.encrypted) {
      html += '<details class="log-wire"><summary data-testid="log-wire-toggle">Wire value</summary><pre>' + escHtml(logPayloadText(payload.wire)) + '</pre></details>';
    }
    return html + '</section>';
  }

  function renderLogDecoderLink(value, label = 'Open in decoder', attributes = {}) {
    const data = Object.entries(attributes).map(([key, val]) => ' data-' + key + '="' + escHtml(String(val)) + '"').join('');
    return '<a class="btn log-decoder-link" data-testid="log-decoder-link"' + data + ' href="decoder/?credential=' + encodeURIComponent(value) +
      '" target="_blank" rel="noopener">' + escHtml(label) + '</a>';
  }

  function renderLogPresentations(presentations) {
    let html = '';
    for (const presentation of presentations) {
      const label = "Open '" + presentation.queryID + "' in decoder" + (presentation.tokenIndex > 0 ? ' (' + (presentation.tokenIndex + 1) + ')' : '');
      html += renderLogDecoderLink(presentation.token, label, { 'query-id': presentation.queryID, 'token-index': presentation.tokenIndex });
    }
    return html;
  }

  function renderLogDetails(details) {
    const isObj = v => typeof v === 'object' && v !== null;
    const keys = Object.keys(details).sort((a, b) => {
      if (isObj(details[a]) !== isObj(details[b])) return isObj(details[a]) ? 1 : -1;
      const ia = logKeyOrder.indexOf(a), ib = logKeyOrder.indexOf(b);
      if (ia !== -1 || ib !== -1) return (ia === -1 ? logKeyOrder.length : ia) - (ib === -1 ? logKeyOrder.length : ib);
      return a.localeCompare(b);
    });
    let html = '<div class="log-fields">';
    for (const key of keys) {
      const val = details[key];
      html += '<span class="log-key">' + escHtml(key) + '</span>';
      if (isObj(val)) {
        html += '<span class="log-value"><pre>' + escHtml(JSON.stringify(val, null, 2)) + '</pre></span>';
      } else {
        html += '<span class="log-value">' + escHtml(String(val)) + '</span>';
      }
    }
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
      ? (claimed ? 'A request is waiting for consent.' : 'A request is waiting that no browser claimed.')
      : pending.length + (claimed ? ' requests are waiting for consent.' : ' requests are waiting that no browser claimed.');
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
    const es = new EventSource('api/requests/stream' +
      (actingOwner ? '?owner=' + encodeURIComponent(actingOwner) : ''));
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
        if (navigable(url)) window.location.href = url;
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
      // SSE events are not replayed. Fetch pending state after reconnecting.
      if (streamDropped) {
        streamDropped = false;
        loadPendingRequests();
      }
    });
    es.onerror = () => {
      streamDropped = true;
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }
  let streamDropped = false;

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
    showErrorDialog(err.message, err.detail);
  }

  function showErrorDialog(message, detail) {
    consentRequestOpen = false;
    consentOverlay.classList.add('active');

    var html = '<div class="dialog-title" style="color:var(--danger)">Error</div>' +
      '<div class="dialog-message">' + escHtml(message) + '</div>';

    if (detail) {
      html += '<pre class="error-detail">' + escHtml(detail) + '</pre>';
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-primary" id="error-dismiss">Dismiss</button>' +
    '</div>';

    consentDialog.innerHTML = html;
    document.getElementById('error-dismiss').addEventListener('click', () => {
      closeConsentOverlay();
      fetch('api/error', { method: 'DELETE' }).catch(() => {});
      loadLog();
    });
  }

  // Restrict redirects to web URLs. javascript: and data: URLs could execute content in
  // the wallet origin.
  function navigable(url) {
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
    if (!navigable(result.redirect_uri)) {
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

    consentOverlay.classList.add('active');

    var isSuccess = result.status_code && result.status_code < 400 && !result.error;
    var titleColor = isSuccess ? 'var(--success, #22c55e)' : 'var(--danger)';
    var titleText = isSuccess ? 'Success' : 'Verifier Error';

    var html = '<div class="dialog-title" style="color:' + titleColor + '">' + titleText + ' (HTTP ' + (result.status_code || '?') + ')</div>';

    if (result.error) {
      var errorBody = result.error;
      try {
        var parsed = JSON.parse(errorBody);
        errorBody = JSON.stringify(parsed, null, 2);
      } catch (e) { /* Keep values that cannot be decoded unchanged. */ }
      html += '<pre class="error-detail">' + escHtml(errorBody) + '</pre>';
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-primary" id="result-dismiss">Dismiss</button>' +
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
    const logoImg = display.logo_uri
      ? '<img class="credential-logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
      : '';
    const faceBadge = fmt ? '<span class="format-badge format-badge-face">' + fmt + '</span>' : '';
    const rowBadge = fmt ? '<span class="format-badge format-badge-row">' + fmt + '</span>' : '';
    const faceName = cred.name || typeLabel;
    const nameHtml = '<span class="credential-name">' + escHtml(faceName) + '</span>';
    const typeMeta = cred.name
      ? '<div class="cred-meta"><span class="cred-meta-item"><span class="cred-meta-k">type</span> <span class="mono">' + escHtml(typeLabel) + '</span></span></div>'
      : '';
    const card = '<div class="credential-card">' +
        '<div class="card-face">' + faceBadge + logoImg + '<div class="face-name">' + escHtml(faceName) + '</div></div>' +
        '<div class="credential-info">' +
          '<div class="credential-type cred-hdr">' + rowBadge + nameHtml + '</div>' +
          typeMeta +
          (cred.description ? '<div class="offer-description">' + linkifyText(cred.description) + '</div>' : '') +
        '</div>' +
      '</div>';
    let claims = '';
    if (cred.claims && cred.claims.length > 0) {
      claims = '<div class="cl-hd">↗ You will receive<span class="cl-count">' + cred.claims.length +
          ' claim' + (cred.claims.length === 1 ? '' : 's') + '</span></div>' +
        '<div class="consent-claims offer-claims">' + cred.claims.map(claim =>
          '<div class="consent-claim"><span class="consent-claim-name mono">' + escHtml(claim).replace(/\./g, '.<wbr>') + '</span></div>'
        ).join('') + '</div>';
    }
    return '<div class="consent-credential" data-config-id="' + escHtml(cred.id) + '">' + card + claims + '</div>';
  }

  function renderOfferDetails(req) {
    const details = req.offer_details || {};
    let html = '';

    const facts = [];
    if (details.grant) facts.push(['Flow', details.grant]);
    if (facts.length > 0) {
      html += '<div class="offer-facts" id="offer-facts">' + facts.map(([k, v]) =>
        '<div><span class="offer-fact-name">' + escHtml(k) + '</span>' +
        '<span class="offer-fact-value">' + escHtml(v) + '</span></div>'
      ).join('') + '</div>';
    }

    // The issuer sends the transaction code separately. Collect it before approving the
    // offer.
    if (details.tx_code) {
      const numeric = details.tx_code_input_mode !== 'text';
      html += '<div class="offer-tx-code">' +
        '<label for="offer-tx-code-input">Transaction code</label>' +
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
      html += '<p class="dialog-hint" id="offer-resolve-error">Could not retrieve the offer. ' +
        'Showing only its issuer. Approve to retry.</p>';
      return html;
    }

    const credentials = details.credentials || [];
    if (credentials.length === 0) {
      (req.offer_configs || []).forEach(cfg => {
        html += '<div class="consent-credential"><div class="consent-credential-header">' +
          '<span style="font-size:12px;font-weight:600;">' + escHtml(cfg) + '</span>' +
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
    const selection = { editing: false, setChoices: [], picks: {}, claims: {} };
    let submitting = false;
    // A query that sets multiple presents every candidate unless the user withholds
    // some. Any other query presents its first candidate.
    function defaultPicks(q) {
      return q.multiple ? q.candidates.map(c => c.credential_id) : [q.candidates[0].credential_id];
    }
    if (options) {
      selection.setChoices = (options.sets || []).map(() => 0);
      options.queries.forEach(q => {
        selection.picks[q.id] = defaultPicks(q);
        q.candidates.forEach(c => {
          // A credential used for two queries shares one merged disclosure selection.
          const kept = selection.claims[c.credential_id] || [];
          Object.keys(c.claims || {}).forEach(key => {
            if (!kept.includes(key)) kept.push(key);
          });
          selection.claims[c.credential_id] = kept;
        });
      });
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
    // Picked candidates in candidate order.
    function activeCandidates(qid) {
      const q = queryById(qid);
      const picked = q.candidates.filter(c => selection.picks[qid].includes(c.credential_id));
      return picked.length > 0 ? picked : [q.candidates[0]];
    }
    function hasAlternatives() {
      if (!options) return false;
      if ((options.sets || []).some(s => s.options.length > 1 || s.optional)) return true;
      return options.queries.some(q => q.candidates.length > 1);
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
      return '<div class="consent-multiple-note" id="consent-multiple-' + escHtml(qid) + '">' +
        'The verifier accepts several credentials here. Sending ' + sent + ' of ' + q.candidates.length + ' matching credentials.</div>';
    }
    function isAutoSelection() {
      return selection.setChoices.every(c => c === 0) &&
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
        options.queries.forEach(q => q.candidates.forEach(c => add(c.credential_id)));
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
        name = d.issuer_name || '';
        cid = d.issuer || req.client_id || '';
        if (d.issuer_logo) {
          logoHtml = '<img class="who-logo" src="' + escHtml(d.issuer_logo) + '" alt="' + escHtml((name || 'Issuer') + ' logo') + '">';
        }
      } else {
        name = req.client_name || '';
        cid = req.client_id || '';
        const auth = req.client_auth;
        if (auth) {
          chip = auth.signed
            ? '<span class="who-chip who-ok" title="Signature matches the supplied key. Signer trust is unchecked.">✓ Signed</span>'
            : '<span class="who-chip who-bad" title="' + escHtml(auth.detail || 'Unsigned request. The sender cannot be authenticated. Anyone can send requests to a shared demo.') + '">✗ Not authenticated</span>';
        }
      }
      const idLine = '<span class="mono">' + escHtml(cid) + '</span>';
      let nameHtml, sub;
      if (name) {
        nameHtml = '<span class="who-name">' + escHtml(name) + '</span>';
        sub = '<div class="who-cid" id="offer-issuer-origin">' + idLine + '</div>';
      } else {
        nameHtml = '<span class="who-name mono" id="offer-issuer-origin">' + escHtml(cid) + '</span>';
        sub = '';
      }
      return '<div class="who">' + logoHtml + '<div class="who-text"><div class="who-nm">' + nameHtml + chip + '</div>' + sub + '</div></div>';
    }

    function headerHtml() {
      let html = '<div class="consent-title">' + (isIssuance ? 'Credential Offer' : 'Presentation Request') + '</div>' +
        whoBlock();

      // Verifier purposes come from registration certificates in verifier_info (OpenID4VP
      // 1.0 §5.1).
      if (!isIssuance && req.purposes) {
        req.purposes.forEach((text, idx) => {
          html += '<div class="consent-purpose" id="consent-purpose-' + idx + '">' +
            '<span class="consent-purpose-label">Purpose</span>' + escHtml(text) + '</div>';
        });
      }
      return html;
    }

    // Allow required claims to be unchecked so developers can test verifier behavior.
    // Keep warnings visible without hover because touch screens have no hover state.
    function warnMarker(hint) {
      return '<span class="consent-claim-hint"><span class="consent-claim-warn" aria-hidden="true">⚠</span>' + escHtml(hint) + '</span>';
    }

    function claimChecklist(credID, claims, kept, emptyArrays, missing) {
      const keys = Object.keys(claims || {});
      const shared = keys.filter(k => (kept ? kept.includes(k) : true)).length;
      const empties = emptyArrays || [];
      const missingList = missing || [];
      const total = keys.length + missingList.length;
      let rows = '';
      keys.forEach(key => {
        // Selecting an array without its selectively disclosable elements reveals an empty
        // array.
        const empty = empties.includes(key);
        const val = empty ? '[]'
          : (typeof claims[key] === 'object' ? JSON.stringify(claims[key]) : String(claims[key]));
        const warn = empty ? warnMarker('Empty array disclosed. Use a null or index path for the values.') : '';
        const checked = kept ? kept.includes(key) : true;
        rows += '<label class="consent-claim">' +
          '<input type="checkbox"' + (checked ? ' checked' : '') + ' data-cred="' + credID + '" data-claim="' + escHtml(key) + '">' +
          '<span class="consent-claim-name mono">' + escHtml(key) + '</span>' +
          '<span class="consent-claim-value mono">' + escHtml(val) + '</span>' + warn +
        '</label>';
      });
      // Debug mode includes missing claims so the mismatch remains visible.
      missingList.forEach(path => {
        rows += '<div class="consent-claim consent-claim-missing">' +
          '<input type="checkbox" disabled aria-hidden="true">' +
          '<span class="consent-claim-name mono">' + escHtml(path) + '</span>' +
          '<span class="consent-claim-value mono">(not disclosed)</span>' +
          warnMarker('Not provided by the selected credential.') +
        '</div>';
      });
      return '<div class="cl-hd">↗ Shared with the verifier<span class="cl-count">' +
          shared + ' of ' + total + ' field' + (total === 1 ? '' : 's') + '</span></div>' +
        '<div class="consent-claims">' + rows + '</div>';
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
      return '<div class="consent-credential" id="consent-credential-' + mc.credential_id + '" data-credential-id="' + mc.credential_id + '" data-vct="' + escHtml(mc.vct || '') + '" data-doctype="' + escHtml(mc.doctype || '') + '">' +
        '<div class="credential-card' + (cred.batch ? ' batch' : '') + '">' + body.html + '</div>' +
        untrustedAuthorityNote(mc) +
        claimChecklist(mc.credential_id, mc.claims, kept, mc.empty_array_claims, mc.missing_claims) +
      '</div>';
    }

    // Debug mode offers credentials that fail trusted_authorities. Explain the mismatch
    // before consent.
    function untrustedAuthorityNote(mc) {
      if (!mc || !mc.untrusted_authority) return '';
      return '<div class="consent-untrusted" role="note">⚠ Could not match this issuer to the verifier\'s trusted authorities. ' +
        'This credential is allowed ' +
        'because debug mode ignores that restriction.</div>';
    }


    function editScreenHtml() {
      let html = headerHtml() +
        '<div class="consent-selection-row">Selection' +
        (isAutoSelection() ? '' : '<button class="link-btn" id="consent-selection-reset">reset to auto</button>') +
        '<button class="btn" id="consent-selection-done">Done</button></div>';

      (options.sets || []).forEach((set, i) => {
        if (set.options.length === 1 && !set.optional) return;
        html += '<div class="consent-sets" id="consent-set-' + i + '" data-set="' + i + '"><span class="consent-section-label">The verifier accepts one of</span>';
        set.options.forEach((opt, j) => {
          html += '<label class="consent-set-option">' +
            '<input type="radio" id="consent-set-' + i + '-option-' + j + '" name="consent-set-' + i + '" value="' + j + '"' + (selection.setChoices[i] === j ? ' checked' : '') + '>' +
            opt.map(id => '<span class="query-chip">' + escHtml(id) + '</span>').join(' + ') +
            (j === 0 ? ' <span class="auto-chip">auto</span>' : '') +
          '</label>';
        });
        if (set.optional) {
          // A presentation needs at least one credential, so the last selected set cannot
          // be skipped.
          const othersAnswered = selection.setChoices.some((c, j) => j !== i && c !== -1);
          html += '<label class="consent-set-option">' +
            '<input type="radio" id="consent-set-' + i + '-none" name="consent-set-' + i + '" value="-1"' +
            (selection.setChoices[i] === -1 ? ' checked' : '') +
            (othersAnswered ? '' : ' disabled') +
            '><span class="query-chip">none</span></label>';
        }
        html += '</div>';
      });

      activeQueryIds().forEach(qid => {
        const q = queryById(qid);
        // A query that sets multiple accepts any number of its candidates, at least one.
        const multi = !!q.multiple;
        html += '<div class="consent-credential" id="consent-query-' + escHtml(qid) + '" data-query-id="' + escHtml(qid) + '"' +
          (multi ? ' data-multiple="true" role="group" aria-label="Credentials answering ' : ' role="radiogroup" aria-label="Credential answering ') + escHtml(qid) + '">' +
          '<div class="consent-credential-header">' +
            '<span class="query-id-label">' + escHtml(qid) + '</span>' +
            '<span class="candidate-count">' + q.candidates.length +
              (q.candidates.length === 1 ? ' credential matches' : ' of your credentials match') +
              (multi ? ' · send one or more' : '') + '</span>' +
          '</div>';
        q.candidates.forEach((c, i) => {
          const picked = selection.picks[qid].includes(c.credential_id);
          // Full credential details are needed to show claims beyond those requested.
          const detail = candidateDetails.get(c.credential_id);
          const body = credentialCardBody(detail || {
            id: c.credential_id, format: c.format, vct: c.vct, doctype: c.doctype, claims: c.claims,
          }, 'candidate-');
          html += '<div class="candidate' + (picked ? ' selected' : '') + '" id="consent-candidate-' + escHtml(qid) + '-' + c.credential_id + '" data-query="' + escHtml(qid) + '" data-cred="' + c.credential_id + '" tabindex="0" role="' + (multi ? 'checkbox' : 'radio') + '" aria-checked="' + picked + '" aria-label="' + escHtml(c.vct || c.doctype || c.format) + '">' +
            '<div class="candidate-row">' +
              '<input type="' + (multi ? 'checkbox' : 'radio') + '" name="consent-pick-' + escHtml(qid) + '"' + (picked ? ' checked' : '') + ' tabindex="-1" aria-hidden="true">' +
              '<div class="credential-card' + (detail && detail.batch ? ' batch' : '') + '">' + body.html + '</div>' +
              '<div class="candidate-actions">' +
                (multi || i === 0 ? '<span class="auto-chip">auto</span>' : '') +
                // Open decoding in another tab to preserve pending consent.
                '<a class="btn btn-sm candidate-decode" id="consent-decode-' + escHtml(qid) + '-' + c.credential_id + '"' +
                  ' href="decoder/?id=' + encodeURIComponent(c.credential_id) + '" target="_blank" rel="noopener"' +
                  ' title="Open in decoder">Show</a>' +
              '</div>' +
            '</div>' + untrustedAuthorityNote(c) + '</div>';
        });
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
        selection.setChoices = (options.sets || []).map(() => 0);
        options.queries.forEach(q => { selection.picks[q.id] = defaultPicks(q); });
        renderDialog();
      });
      consentDialog.querySelectorAll('.consent-sets input[type="radio"]').forEach(radio => {
        radio.addEventListener('change', () => {
          const setIdx = Number(radio.closest('.consent-sets').dataset.set);
          selection.setChoices[setIdx] = Number(radio.value);
          renderDialog();
        });
      });
      consentDialog.querySelectorAll('.candidate').forEach(el => {
        const choose = () => {
          const qid = el.dataset.query;
          const picks = selection.picks[qid];
          if (queryById(qid).multiple) {
            const idx = picks.indexOf(el.dataset.cred);
            // A presentation answers the query with at least one credential.
            if (idx >= 0 && picks.length === 1) return;
            if (idx >= 0) picks.splice(idx, 1); else picks.push(el.dataset.cred);
            renderDialog();
          } else if (picks[0] !== el.dataset.cred) {
            selection.picks[qid] = [el.dataset.cred];
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
        html += '<div class="consent-selection-row" id="consent-selection-row">' +
          (isAutoSelection()
            ? 'Auto-selected' + (n > 0 ? ' · ' + n + (n === 1 ? ' alternative' : ' alternatives') : '')
            : 'Your selection (auto-choice changed)') +
          '<button class="btn" id="consent-edit-selection">Edit</button></div>';
      }
      activeQueryIds().forEach(qid => {
        html += multipleNote(qid);
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

    consentDialog.innerHTML = html;
    wireSelectionHandlers();

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

      // Edit has no claim checkboxes. Read its tracked selection when alternatives are
      // available.
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

      const approveBtn = document.getElementById('consent-approve');
      const denyBtn = document.getElementById('consent-deny');
      submitting = true;
      consentSubmitting = true;
      approveBtn.disabled = true;
      approveBtn.textContent = 'Submitting...';
      expectError();
      denyBtn.disabled = true;

      try {
        const txCodeInput = document.getElementById('offer-tx-code-input');
        const approveBody = isIssuance
          ? (txCodeInput ? { tx_code: txCodeInput.value.trim() } : {})
          : { selected_claims: selected };
        if (options) {
          approveBody.picks = {};
          activeQueryIds().forEach(qid => {
            const ids = activeCandidates(qid).map(c => c.credential_id);
            approveBody.picks[qid] = queryById(qid).multiple ? ids : ids[0];
          });
          approveBody.set_choices = selection.setChoices.slice();
        }
        const resp = await fetch(approveURL(req.id, '/approve'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(approveBody)
        });
        const result = await resp.json();
        // A nested presentation can replace the issuance dialog before approval returns.
        // Do not update the replacement with the earlier result.
        if (consentRequestID !== req.id) return;
        if (!resp.ok) {
          showErrorDialog('This request could not be answered', result.error || 'The wallet refused the answer.');
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
            const detail = result.error || ('HTTP ' + result.status_code);
            showErrorDialog('Credential issuance failed', detail);
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
          showErrorDialog('This request could not be denied', result.error || 'The wallet refused the answer.');
          return;
        }
        if (followVerifierRedirect(result)) return;
      } catch (e) {
        console.error('Deny failed:', e);
      } finally {
        consentSubmitting = false;
      }
      closeConsentOverlay();
      await loadLog();
    });
    }

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

  // Escape descriptions and link only HTTP or HTTPS URLs. Escape href values to prevent
  // injected attributes.
  function linkifyText(s) {
    return escHtml(s).replace(/https?:\/\/[^\s<>"']+/g, function (url) {
      return '<a href="' + url + '" target="_blank" rel="noopener">' + url + '</a>';
    });
  }

  // The news of a public demo opens once per version of its content. A
  // consent link opens no news, so it can't cover the request.
  const newsOverlay = document.getElementById('news-overlay');
  async function showNews(id) {
    const link = document.getElementById('news-link');
    const open = async () => {
      const resp = await fetch('api/news');
      if (!resp.ok) return;
      document.getElementById('news-content').innerHTML = (await resp.json()).html;
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
  // Wait for configuration before deciding to open consent automatically. Demo mode uses
  // different ownership rules.
  async function loadAppConfig() {
    try {
      const resp = await fetch('api/config');
      const config = await resp.json();
      if (config.version) {
        window.EUDI_VERSION = config.version;
        document.getElementById('footer-version').textContent = 'eudi-dev ' + config.version;
      }
      if (config.imprint) {
        document.getElementById('imprint-link').hidden = false;
      }
      if (config.news_id) {
        showNews(config.news_id);
      }
      if (config.tls_listener === false) {
        // An external TLS terminator does not use the wallet's TLS certificate, so hide
        // that download.
        document.getElementById('tls-row-label').hidden = true;
        document.getElementById('tls-row').hidden = true;
      }
      demoMode = !!(config.demo && config.demo.enabled);
      renderAutoAccept(!!config.auto_accept);
      renderConformance(config);
      ['conf-mode-select', 'conf-tls-select', 'conf-haip-input', 'conf-encrypted-input', 'conf-vci-version-select', 'conf-key-attestation-select'].forEach((id) => {
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
        document.getElementById('issue-save-template').hidden = true;
        document.querySelector('label[for="issue-save-template"]').hidden = true;
        document.getElementById('template-form').hidden = true;
        document.getElementById('templates-btn').hidden = true;
        // Demo mode accepts images from templates and issuer metadata, but rejects visitor
        // image fields.
        document.querySelectorAll('.issue-image-field').forEach((el) => { el.hidden = true; });
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

  // Conformance settings apply to the wallet process. Demo mode displays them without
  // allowing changes.
  let conformanceDefaults = { validation_mode: 'debug', require_haip: true, require_encrypted_request: false, vci_version: '1.0', key_attestation_level: '' };

  function effectiveConformance() {
    return {
      mode: conformanceDefaults.validation_mode === 'strict' ? 'strict' : 'debug',
      tls: conformanceDefaults.tls_verify_override == null ? 'auto' : String(conformanceDefaults.tls_verify_override),
      haip: !!conformanceDefaults.require_haip,
      encrypted: !!conformanceDefaults.require_encrypted_request,
      vciVersion: conformanceDefaults.vci_version === '1.1' ? '1.1' : '1.0',
      keyAttestationLevel: conformanceDefaults.key_attestation_level || '',
    };
  }

  function applyConformanceToControls() {
    const eff = effectiveConformance();
    const mode = document.getElementById('conf-mode-select');
    const tls = document.getElementById('conf-tls-select');
    const haip = document.getElementById('conf-haip-input');
    const enc = document.getElementById('conf-encrypted-input');
    const vci = document.getElementById('conf-vci-version-select');
    const level = document.getElementById('conf-key-attestation-select');
    if (tls) { tls.value = eff.tls; tls.disabled = demoMode; }
    if (mode) { mode.value = eff.mode === 'strict' ? 'strict' : 'debug'; mode.disabled = demoMode; }
    if (haip) { haip.checked = eff.haip; haip.disabled = demoMode; }
    if (enc) { enc.checked = eff.encrypted; enc.disabled = demoMode; }
    if (vci) { vci.value = eff.vciVersion; vci.disabled = demoMode; }
    if (level) { level.value = eff.keyAttestationLevel; level.disabled = demoMode; }
  }

  function currentControlValues() {
    const mode = document.getElementById('conf-mode-select');
    const tls = document.getElementById('conf-tls-select');
    const haip = document.getElementById('conf-haip-input');
    const enc = document.getElementById('conf-encrypted-input');
    const vci = document.getElementById('conf-vci-version-select');
    const level = document.getElementById('conf-key-attestation-select');
    return {
      mode: mode ? mode.value : undefined,
      tls_verify: !tls || tls.value === 'auto' ? null : tls.value === 'true',
      haip: haip ? haip.checked : undefined,
      encrypted: enc ? enc.checked : undefined,
      vci_version: vci ? vci.value : undefined,
      key_attestation_level: level ? level.value : undefined,
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

  function onConformanceChange() {
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
    set('conf-transcript', config.session_transcript || 'oid4vp', 'neutral');
    set('conf-format', config.preferred_format || 'no preference',
      config.preferred_format ? 'neutral' : 'off');
    const intro = document.getElementById('conf-intro');
    if (intro) {
      const base = 'Debug mode reports failed checks. Strict mode rejects invalid requests. HTTPS verification is on by default in strict mode and off in debug mode. You can override it in either mode.';
      intro.textContent = demoMode ? base + ' Settings are fixed on the public demo.' : base;
    }
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

  // Issuance can add trust profiles, so refresh links when credentials change.
  async function loadTrustLists() {
    const row = document.getElementById('trust-list-links');
    try {
      const resp = await fetch('api/trustlists');
      const doc = await resp.json();
      const lists = (doc && doc.trust_lists) || [];
      row.querySelectorAll('.trust-items').forEach(el => el.remove());
      row.hidden = lists.length === 0;

      const groups = new Map();
      lists.forEach(entry => {
        const category = entry.category || 'Other';
        if (!groups.has(category)) groups.set(category, []);
        groups.get(category).push(entry);
      });

      const list = document.createElement('dl');
      list.className = 'trust-items';
      [...groups.keys()].sort().forEach(category => {
        const term = document.createElement('dt');
        term.textContent = category;
        list.appendChild(term);

        const detail = document.createElement('dd');
        groups.get(category)
          .slice()
          .sort((a, b) => (a.id || '').localeCompare(b.id || ''))
          .forEach(entry => {
            const url = entry.advertised_url || entry.url ||
              (entry.path ? window.location.origin + entry.path : '');
            if (!url) return;
            const links = document.createElement('span');
            links.className = 'trust-links';
            const link = document.createElement('a');
            link.href = url;
            link.textContent = entry.id || 'trust list';
            link.title = url;
            links.appendChild(link);
            if (entry.entityName) {
              const name = document.createElement('span');
              name.className = 'trust-list-name';
              name.textContent = entry.entityName;
              links.appendChild(name);
            }
            const copy = document.createElement('button');
            copy.type = 'button';
            copy.className = 'copy-btn';
            copy.textContent = '\u29C9';
            copy.title = 'Copy trust list URL';
            copy.addEventListener('click', async () => {
              try {
                await navigator.clipboard.writeText(url);
                copy.textContent = '\u2713';
                setTimeout(() => { copy.textContent = '\u29C9'; }, 1200);
              } catch (e) { /* The clipboard API may be unavailable. */ }
            });
            links.appendChild(copy);
            detail.appendChild(links);
            if (entry.description) {
              const desc = document.createElement('span');
              desc.className = 'trust-item-hint';
              desc.textContent = entry.description;
              detail.appendChild(desc);
            }
          });
        list.appendChild(detail);
      });
      row.appendChild(list);
    } catch (e) {
      row.hidden = true;
    }
  }

  const trustOverlay = document.getElementById('trust-overlay');
  document.getElementById('trust-link').addEventListener('click', (event) => {
    event.preventDefault();
    loadTrustLists();
    trustOverlay.classList.add('active');
  });
  document.getElementById('trust-close').addEventListener('click', () => {
    trustOverlay.classList.remove('active');
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
    howtoOverlay.classList.add('active');
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
  loadAppConfigPromise.then(loadPendingRequests);
  connectSSE();
})();
