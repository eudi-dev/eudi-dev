// Runs in the page. Replaces the Digital Credentials API (W3C Digital
// Credentials, navigator.credentials.get() with a digital member) and passes
// each request to bridge.js, which forwards it to the eudi-dev wallet.
(() => {
  'use strict';
  // The API exists only in secure contexts.
  if (!window.isSecureContext || !navigator.credentials) return;

  const SOURCE = 'eudi-dev-dc-api';
  // The presentation protocols of W3C Digital Credentials §5 that the wallet
  // answers.
  const PROTOCOLS = ['openid4vp-v1-unsigned', 'openid4vp-v1-signed', 'openid4vp-v1-multisigned'];

  class DigitalCredential {
    #protocol;
    #data;
    constructor(protocol, data) {
      this.#protocol = protocol;
      this.#data = data;
    }
    get id() { return ''; }
    get type() { return 'digital'; }
    get protocol() { return this.#protocol; }
    get data() { return this.#data; }
    toJSON() { return { protocol: this.#protocol, data: this.#data }; }
    static userAgentAllowsProtocol(protocol) { return PROTOCOLS.includes(protocol); }
  }
  Object.defineProperty(window, 'DigitalCredential', { value: DigitalCredential, writable: true, configurable: true });
  // Lets a page tell this extension from the browser's own API.
  Object.defineProperty(window, 'eudiDevDigitalCredentials', { value: true });

  const pending = new Map();
  window.addEventListener('message', (event) => {
    const msg = event.data;
    if (event.source !== window || !msg || msg.source !== SOURCE || msg.direction !== 'to-page') return;
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    if (msg.result) entry.resolve(new DigitalCredential(msg.result.protocol, msg.result.data));
    else entry.reject(new DOMException(msg.error.message, msg.error.name));
  });

  function cloneCall(digital) {
    try {
      return JSON.parse(JSON.stringify({ digital }));
    } catch (e) {
      return undefined;
    }
  }

  function post(message) {
    window.postMessage({ source: SOURCE, direction: 'to-extension', ...message }, location.origin);
  }

  // refuse rejects a call like a browser would. The extension logs the
  // refusal to the page console and the wallet's activity log.
  function refuse(digital, name, message) {
    post({ type: 'refused', name, message, request: cloneCall(digital) });
    return Promise.reject(name === 'TypeError' ? new TypeError(message) : new DOMException(message, name));
  }

  // The Permissions Policy feature digital-credentials-get (W3C Digital
  // Credentials §9). A browser that doesn't know the feature has no policy
  // to check.
  function allowedInThisFrame() {
    const policy = document.featurePolicy;
    if (!policy || !policy.features().includes('digital-credentials-get')) return true;
    return policy.allowsFeature('digital-credentials-get');
  }

  // Runs the checks of W3C Digital Credentials §6.2 that a browser makes
  // before a request reaches a wallet, so a verifier page fails here where
  // it would fail in a browser.
  function getDigital(options) {
    const signal = options.signal;
    if (signal && signal.aborted) return Promise.reject(signal.reason);
    const all = options.digital && options.digital.requests;
    if (!Array.isArray(all)) return refuse(options.digital, 'TypeError', 'digital.requests must be an array');
    // §6.2 drops requests with a protocol the browser doesn't support.
    const requests = all.filter((r) => r && PROTOCOLS.includes(r.protocol));
    if (requests.length === 0) {
      return refuse(options.digital, 'TypeError', 'No request uses a supported protocol (' + PROTOCOLS.join(', ') + ')');
    }
    if (requests.some((r) => r.data === null || typeof r.data !== 'object')) {
      return refuse(options.digital, 'TypeError', 'The data of an OpenID4VP request must be an object');
    }
    if (!allowedInThisFrame()) {
      return refuse(options.digital, 'NotAllowedError', 'The permissions policy digital-credentials-get does not allow this frame');
    }
    if (document.visibilityState !== 'visible' || !document.hasFocus()) {
      return refuse(options.digital, 'NotAllowedError', 'The page must be visible and have focus');
    }
    if (navigator.userActivation && !navigator.userActivation.isActive) {
      return refuse(options.digital, 'NotAllowedError', 'navigator.credentials.get() needs a user action, such as a click, shortly before the call');
    }
    if (pending.size > 0) {
      return refuse(options.digital, 'NotAllowedError', 'Another Digital Credentials API request of this page is still open');
    }
    // The wallet gets every request. Its activity log explains each
    // unanswered one.
    let request = cloneCall({ requests: all });
    if (!request) {
      try {
        request = JSON.parse(JSON.stringify({ digital: { requests } }));
      } catch (e) {
        return Promise.reject(e);
      }
    }
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      if (signal) {
        signal.addEventListener('abort', () => {
          if (!pending.delete(id)) return;
          post({ type: 'abort', id });
          reject(signal.reason);
        }, { once: true });
      }
      post({ type: 'get', id, request });
    });
  }

  const nativeGet = navigator.credentials.get.bind(navigator.credentials);
  navigator.credentials.get = function get(options) {
    if (!options || options.digital === undefined) return nativeGet(options);
    return getDigital(options);
  };
})();
