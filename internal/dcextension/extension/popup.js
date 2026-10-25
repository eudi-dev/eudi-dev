const input = document.getElementById('wallet-url');
const status = document.getElementById('status');
const open = document.getElementById('open');

function show(text, kind) {
  status.textContent = text;
  status.className = kind || '';
}

async function check(walletURL) {
  open.href = walletURL + '/';
  show('Checking the wallet…');
  try {
    const resp = await fetch(walletURL + '/', { credentials: 'omit' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    show(`The wallet answers at ${walletURL}.`, 'ok');
  } catch (e) {
    show(`No wallet answers at ${walletURL}.`, 'bad');
  }
}

let configured = '';

async function load() {
  const { walletURL, savedFor } = await chrome.storage.local.get(['walletURL', 'savedFor']);
  configured = (await (await fetch(chrome.runtime.getURL('config.json'))).json()).wallet_url;
  input.value = walletURL && savedFor === configured ? walletURL : configured;
  check(input.value.replace(/\/+$/, ''));
}

document.getElementById('save').addEventListener('click', async () => {
  let url;
  try {
    url = new URL(input.value.trim());
  } catch (e) {
    show('Enter a URL such as http://localhost:8085.', 'bad');
    return;
  }
  const walletURL = (url.origin + url.pathname).replace(/\/+$/, '');
  input.value = walletURL;
  await chrome.storage.local.set({ walletURL, savedFor: configured });
  check(walletURL);
});

// Turns the page console logging of calls on or off.
const consoleLog = document.getElementById('console-log');
chrome.storage.local.get('consoleLog').then(({ consoleLog: on }) => { consoleLog.checked = on !== false; });
consoleLog.addEventListener('change', () => chrome.storage.local.set({ consoleLog: consoleLog.checked }));

load();
