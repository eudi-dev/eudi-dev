// Starts each request: makes sure the offscreen document runs, returns the
// settings and opens the wallet in a window, so the user can answer the
// consent. A wallet that answers at once, such as one with --auto-accept,
// gets no window.
const WINDOW_DELAY_MS = 500;
const DEFAULT_SETTINGS_URL = chrome.runtime.getURL('config.json');
const timers = new Map();

// A wallet URL saved in the popup applies only to the extension it was saved
// in. An extension written for another wallet, for example by
// `eudi wallet browser`, uses its own config.json.
async function settings() {
  const stored = await chrome.storage.local.get(['walletURL', 'savedFor', 'owner', 'consoleLog']);
  const configured = (await (await fetch(DEFAULT_SETTINGS_URL)).json()).wallet_url;
  const walletURL = stored.walletURL && stored.savedFor === configured ? stored.walletURL : configured;
  let owner = stored.owner;
  if (!owner) {
    owner = crypto.randomUUID();
    await chrome.storage.local.set({ owner });
  }
  return { walletURL: walletURL.replace(/\/+$/, ''), owner, consoleLog: stored.consoleLog !== false };
}

// A refused call is reported at most once a minute, even when the page
// retries it in a loop.
const REFUSAL_INTERVAL_MS = 60 * 1000;
const reported = new Map();

// reportRefusal sends a refused call to the wallet's activity log. Wallets
// before 3.5.0 don't have the endpoint and reject the report.
async function reportRefusal(msg, origin) {
  const key = origin + '\n' + msg.name + '\n' + msg.message;
  const now = Date.now();
  for (const [k, at] of reported) if (now - at >= REFUSAL_INTERVAL_MS) reported.delete(k);
  if (reported.has(key)) return;
  reported.set(key, now);
  const { walletURL, owner } = await settings();
  await fetch(walletURL + '/api/dc-api/refusals', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Eudi-Owner': owner, 'X-Eudi-Caller-Origin': origin },
    body: JSON.stringify({ name: msg.name, message: msg.message, request: msg.request }),
    credentials: 'omit',
  });
}

async function ensureOffscreen() {
  if (await chrome.offscreen.hasDocument()) return;
  await chrome.offscreen.createDocument({
    url: 'offscreen.html',
    reasons: ['WORKERS'],
    justification: 'Waits for the wallet to answer a Digital Credentials API request, which can take minutes.',
  }).catch((e) => {
    // Two requests at once both try to create it.
    if (!String(e.message).includes('single offscreen')) throw e;
  });
}

async function openWallet(id, { walletURL, owner }) {
  const url = `${walletURL}/?focus=overview&owner=${encodeURIComponent(owner)}`;
  const win = await chrome.windows.create({ url, type: 'popup', width: 520, height: 820, focused: true });
  const { windows = {} } = await chrome.storage.session.get('windows');
  windows[id] = win.id;
  await chrome.storage.session.set({ windows });
}

async function closeWallet(id) {
  clearTimeout(timers.get(id));
  timers.delete(id);
  const { windows = {} } = await chrome.storage.session.get('windows');
  const windowId = windows[id];
  if (windowId === undefined) return;
  delete windows[id];
  await chrome.storage.session.set({ windows });
  await chrome.windows.remove(windowId).catch(() => {});
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {
    case 'dc-start':
      (async () => {
        const current = await settings();
        await ensureOffscreen();
        timers.set(msg.id, setTimeout(() => {
          timers.delete(msg.id);
          openWallet(msg.id, current);
        }, WINDOW_DELAY_MS));
        return current;
      })().then(sendResponse, (e) => sendResponse({ error: e.message }));
      return true;
    case 'dc-settings':
      settings().then(sendResponse, () => sendResponse({}));
      return true;
    case 'dc-refused':
      reportRefusal(msg, sender.origin || new URL(sender.url).origin).catch(() => {});
      return false;
    case 'dc-finished':
      closeWallet(msg.id);
      return false;
    case 'dc-abort':
      chrome.runtime.sendMessage({ type: 'dc-cancel', id: msg.id, reason: 'The page aborted the request' }).catch(() => {});
      closeWallet(msg.id);
      return false;
  }
  return false;
});

// Closing the wallet window cancels its request, like closing the browser's
// credential picker.
chrome.windows.onRemoved.addListener(async (windowId) => {
  const { windows = {} } = await chrome.storage.session.get('windows');
  for (const [id, wid] of Object.entries(windows)) {
    if (wid !== windowId) continue;
    delete windows[id];
    await chrome.storage.session.set({ windows });
    chrome.runtime.sendMessage({ type: 'dc-cancel', id, reason: 'The wallet window was closed' }).catch(() => {});
  }
});

// A flag in page.js can't turn the extension off. page.js replaces the API in
// the page before it could read storage. So the scripts are registered here, and
// a page gets the browser's own API when they are removed.
const PAGE_SCRIPTS = [
  { id: 'eudi-dev-page', js: ['page.js'], world: 'MAIN', matches: ['<all_urls>'], runAt: 'document_start', allFrames: true },
  { id: 'eudi-dev-bridge', js: ['bridge.js'], matches: ['<all_urls>'], runAt: 'document_start', allFrames: true },
];

async function syncPageScripts() {
  const { enabled } = await chrome.storage.local.get('enabled');
  const registered = await chrome.scripting.getRegisteredContentScripts();
  const ids = registered.map((script) => script.id);
  if (enabled === false || registered.length < PAGE_SCRIPTS.length) {
    if (ids.length > 0) await chrome.scripting.unregisterContentScripts({ ids });
  }
  if (enabled !== false && registered.length < PAGE_SCRIPTS.length) {
    await chrome.scripting.registerContentScripts(PAGE_SCRIPTS);
  }
  await chrome.action.setBadgeText({ text: enabled === false ? 'OFF' : '' });
}

// Runs one at a time, because two runs at once would register the same IDs.
let pageScriptSync = Promise.resolve();
function queuePageScriptSync() {
  pageScriptSync = pageScriptSync.then(syncPageScripts).catch((e) => console.error('eudi-dev extension:', e));
}

chrome.storage.onChanged.addListener((changes) => {
  if (changes.enabled) queuePageScriptSync();
});
chrome.runtime.onInstalled.addListener(queuePageScriptSync);
queuePageScriptSync();
