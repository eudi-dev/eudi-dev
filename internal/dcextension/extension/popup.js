const DEMO_URL = 'https://eudi-test.dev';
const LOCAL_URL = 'http://localhost:8085';
const CHECK_TIMEOUT_MS = 5000;

const input = document.getElementById('wallet-url');
const status = document.getElementById('status');
const hint = document.getElementById('hint');
const open = document.getElementById('open');
const enabled = document.getElementById('enabled');
const wallet = document.getElementById('wallet');
const modeButtons = document.querySelectorAll('[data-mode]');

let configured = '';
let walletURL = '';
let lastCheck = 0;

function showStatus(text, kind) {
  status.textContent = text;
  status.className = kind || '';
}

function showHint(text, bad) {
  hint.textContent = text;
  hint.className = bad ? 'bad' : '';
  input.classList.toggle('bad', !!bad);
}

function isLocal(url) {
  try {
    const { hostname } = new URL(url);
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch (e) {
    return false;
  }
}

function modeOf(url) {
  if (url === DEMO_URL) return 'demo';
  return isLocal(url) ? 'local' : 'custom';
}

function showMode(mode) {
  modeButtons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.mode === mode)));
  input.hidden = mode === 'demo';
}

function localStartHint(url) {
  const { port, protocol } = new URL(url);
  return 'Start it with eudi wallet serve --port ' + (port || (protocol === 'https:' ? '443' : '80'));
}

// A site that answers is not yet a wallet, so the check reads the wallet's own
// version endpoint. Development builds report only a build_id.
async function readWallet(url) {
  let resp;
  try {
    resp = await fetch(url + '/api/version', { credentials: 'omit', signal: AbortSignal.timeout(CHECK_TIMEOUT_MS) });
  } catch (e) {
    return 'unreachable';
  }
  try {
    if (!resp.ok) return 'other';
    const { version, build_id: buildID } = await resp.json();
    return version || buildID ? 'wallet' : 'other';
  } catch (e) {
    return 'other';
  }
}

async function check() {
  open.href = walletURL + '/';
  showHint('');
  const current = ++lastCheck;
  if (!enabled.checked) {
    showStatus("Off. Pages use the browser's Digital Credentials API");
    return;
  }
  const url = walletURL;
  showStatus('Checking the wallet…');
  const found = await readWallet(url);
  if (current !== lastCheck) return;
  if (found === 'wallet') {
    showStatus('Connected to ' + new URL(url).host, 'ok');
  } else if (found === 'other') {
    showStatus("This isn't an eudi-dev wallet", 'bad');
    showHint('The site answers, but no wallet runs there.', true);
  } else {
    showStatus("Can't reach this wallet", 'bad');
    if (modeOf(url) === 'local') showHint(localStartHint(url));
  }
}

async function useWallet(url) {
  walletURL = url;
  input.value = url;
  const stored = { walletURL: url, savedFor: configured };
  if (modeOf(url) === 'local') stored.localURL = url;
  if (modeOf(url) === 'custom') stored.customURL = url;
  await chrome.storage.local.set(stored);
  showMode(modeOf(url));
  await check();
}

modeButtons.forEach(button => button.addEventListener('click', async () => {
  const { mode } = button.dataset;
  if (mode === 'demo') {
    await useWallet(DEMO_URL);
  } else if (mode === 'local') {
    const { localURL } = await chrome.storage.local.get('localURL');
    await useWallet(localURL || (isLocal(configured) ? configured : LOCAL_URL));
  } else {
    const { customURL } = await chrome.storage.local.get('customURL');
    if (customURL) {
      await useWallet(customURL);
    } else {
      showMode('custom');
      input.value = '';
    }
    input.focus();
  }
}));

input.addEventListener('change', () => {
  let url;
  try {
    url = new URL(input.value.trim());
  } catch (e) {
    url = null;
  }
  if (!url || !['http:', 'https:'].includes(url.protocol)) {
    showHint('Enter a URL such as ' + LOCAL_URL + '.', true);
    return;
  }
  useWallet((url.origin + url.pathname).replace(/\/+$/, ''));
});

// With the extension off, background.js removes the page scripts. Open pages
// keep what they loaded until they reload.
const reloadNotice = document.getElementById('reload-notice');
enabled.addEventListener('change', async () => {
  await chrome.storage.local.set({ enabled: enabled.checked });
  wallet.hidden = !enabled.checked;
  reloadNotice.hidden = false;
  check();
});
document.getElementById('reload').addEventListener('click', () => {
  chrome.tabs.reload();
  reloadNotice.hidden = true;
});

const consoleLog = document.getElementById('console-log');
consoleLog.addEventListener('change', () => chrome.storage.local.set({ consoleLog: consoleLog.checked }));

async function load() {
  const stored = await chrome.storage.local.get(['walletURL', 'savedFor', 'enabled', 'consoleLog']);
  configured = (await (await fetch(chrome.runtime.getURL('config.json'))).json()).wallet_url;
  walletURL = (stored.walletURL && stored.savedFor === configured ? stored.walletURL : configured).replace(/\/+$/, '');
  input.value = walletURL;
  enabled.checked = stored.enabled !== false;
  consoleLog.checked = stored.consoleLog !== false;
  wallet.hidden = !enabled.checked;
  showMode(modeOf(walletURL));
  check();
}

load();
