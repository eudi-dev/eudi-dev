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

  window.addEventListener('message', async (event) => {
    const msg = event.data;
    if (event.source !== window || !msg || msg.source !== SOURCE || msg.direction !== 'to-extension') return;
    if (msg.type === 'abort') {
      send({ type: 'dc-abort', id: msg.id }).catch(() => {});
      return;
    }
    if (msg.type !== 'get') return;
    try {
      const settings = await send({ type: 'dc-start', id: msg.id });
      const answer = await send({ type: 'dc-call', id: msg.id, request: msg.request, ...settings });
      reply(msg.id, answer);
    } catch (e) {
      reply(msg.id, { error: { name: 'NotAllowedError', message: 'eudi-dev extension: ' + e.message } });
    }
  });
})();
