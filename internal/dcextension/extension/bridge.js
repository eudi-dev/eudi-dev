// Runs next to page.js in the extension's isolated world. Passes requests
// from the page to the extension and the answers back.
(() => {
  'use strict';
  const SOURCE = 'eudi-dev-dc-api';

  function reply(id, answer) {
    window.postMessage({ source: SOURCE, direction: 'to-page', id, ...answer }, location.origin);
  }

  function send(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (answer) => {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve(answer);
      });
    });
  }

  // logCall writes the request and its result to the page console. The popup
  // can turn this off.
  function logCall({ consoleLog, walletURL }, request, outcome) {
    if (consoleLog === false) return;
    const failed = Boolean(outcome.error);
    console.groupCollapsed('%ceudi-dev%c navigator.credentials.get() ' + (failed ? 'failed' : 'answered'),
      'background:#1f4fd1;color:#fff;border-radius:3px;padding:0 4px', '');
    console.log('Request', request);
    if (failed) console.warn(outcome.error.name + ': ' + outcome.error.message);
    else console.log('Result', outcome.result);
    if (walletURL) console.log('The activity log of the wallet shows each step: ' + walletURL + '/');
    console.groupEnd();
  }

  window.addEventListener('message', async (event) => {
    const msg = event.data;
    if (event.source !== window || !msg || msg.source !== SOURCE || msg.direction !== 'to-extension') return;
    if (msg.type === 'abort') {
      send({ type: 'dc-abort', id: msg.id }).catch(() => {});
      return;
    }
    if (msg.type === 'refused') {
      send({ type: 'dc-refused', name: msg.name, message: msg.message, request: msg.request }).catch(() => {});
      send({ type: 'dc-settings' }).then((settings) => logCall(settings, msg.request, { error: msg }), () => {});
      return;
    }
    if (msg.type !== 'get') return;
    let settings = {};
    let answer;
    try {
      settings = await send({ type: 'dc-start', id: msg.id });
      answer = await send({ type: 'dc-call', id: msg.id, request: msg.request, walletURL: settings.walletURL, owner: settings.owner });
    } catch (e) {
      answer = { error: { name: 'NotAllowedError', message: 'eudi-dev extension: ' + e.message } };
    }
    logCall(settings, msg.request, answer);
    reply(msg.id, answer);
  });
})();
