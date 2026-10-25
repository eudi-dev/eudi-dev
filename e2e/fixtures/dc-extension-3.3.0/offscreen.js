// Answers dc-call messages from bridge.js. The origin comes from the browser's
// sender information, so a page can't claim another origin.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'dc-call') {
    const origin = sender.origin || new URL(sender.url).origin;
    callWallet(msg, origin).then((answer) => {
      chrome.runtime.sendMessage({ type: 'dc-finished', id: msg.id });
      sendResponse(answer);
    });
    return true;
  }
  if (msg.type === 'dc-cancel') abortCall(msg.id, msg.reason);
  return false;
});
