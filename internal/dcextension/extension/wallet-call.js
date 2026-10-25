// Sends a Digital Credentials API request to the wallet's /api/dc-api and
// turns the answer into what navigator.credentials.get() delivers. The call
// waits for the user's consent, so it runs in a page that Chrome keeps alive:
// the offscreen document.
const calls = new Map();

async function callWallet({ id, request, walletURL, owner }, origin) {
  const controller = new AbortController();
  calls.set(id, { controller, walletURL, owner });
  let resp;
  try {
    resp = await fetch(walletURL + '/api/dc-api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Eudi-Owner': owner, 'X-Eudi-Caller-Origin': origin, 'X-Eudi-Call-Id': id },
      body: JSON.stringify(request),
      credentials: 'omit',
      signal: controller.signal,
    });
  } catch (e) {
    if (controller.signal.aborted) return { error: { name: 'NotAllowedError', message: String(controller.signal.reason || 'The request was cancelled') } };
    return { error: { name: 'NotAllowedError', message: `The eudi-dev wallet at ${walletURL} is not reachable. Start it or set its URL in the extension.` } };
  } finally {
    calls.delete(id);
  }
  const body = await resp.json().catch(() => null);
  // OpenID4VP 1.0 Appendix A: a protocol error, such as access_denied, is a
  // fulfilled result too.
  if (resp.ok && body && body.protocol) return { result: { protocol: body.protocol, data: body.data } };
  const reason = (body && (body.error_description || body.error)) || `HTTP ${resp.status}`;
  return { error: { name: 'NotAllowedError', message: 'eudi-dev wallet: ' + reason } };
}

// abortCall sends the reason to the wallet's activity log and then stops the
// call. Wallets before 3.5.0 don't have the endpoint and see only the closed
// connection.
async function abortCall(id, reason) {
  const call = calls.get(id);
  if (!call) return;
  await fetch(call.walletURL + '/api/dc-api/cancel', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Eudi-Owner': call.owner },
    body: JSON.stringify({ id, reason }),
    credentials: 'omit',
    signal: AbortSignal.timeout(2000),
  }).catch(() => {});
  call.controller.abort(reason);
}
