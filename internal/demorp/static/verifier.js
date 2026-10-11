// Stop polling completed requests and pause hidden tabs to limit traffic from abandoned
// pages.
const POLL_MIN = 1500;
const POLL_MAX = 8000;
let pollTimer = null;
let pollDelay = POLL_MIN;
let pollID = null;

// Escape quotes as well as markup because values also appear in attributes.
function esc(s) {
  return String(s === undefined || s === null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function idPart(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "x";
}

function renderResult(doc) {
  const box = document.getElementById("result-box");
  box.style.display = "block";
  const status = document.getElementById("status");
  status.className = "status " + doc.status;
  status.textContent =
    doc.status === "verified" ? "✓ Presentation verified" :
    doc.status === "failed" ? "✗ Verification failed" + (doc.error ? ": " + doc.error : "") :
    doc.status === "expired" ? "Request expired, create a new one" :
    "Waiting for the wallet…";
  const checks = document.getElementById("checks");
  checks.innerHTML = (doc.checks || []).map((c, i) => {
    // A protocol check can pass while reporting a profile warning.
    if (c.ok && c.warning) {
      return `<div class="warn" id="checks-${i}">! ${esc(c.name)}: ${esc(c.warning)}</div>`;
    }
    if (c.ok && c.skipped) {
      return `<div class="skip" id="checks-${i}">– ${esc(c.name)}: ${esc(c.skipped)}</div>`;
    }
    const detail = c.error || c.detail;
    return `<div class="${c.ok ? "ok" : "fail"}" id="checks-${i}">${c.ok ? "✓" : "✗"} ${esc(c.name)}${detail ? ": " + esc(detail) : ""}</div>`;
  }).join("");
  const claims = document.getElementById("claims");
  const label = document.getElementById("claims-label");
  if (doc.status === "verified" && doc.claims) {
    claims.innerHTML = Object.entries(doc.claims).map(([k, v], i) => {
      const id = `claims-${i}-${idPart(k)}`;
      return typeof v === "object" && v !== null
        ? `<tr id="${id}"><td id="${id}-name">${esc(k)}</td><td id="${id}-value"><div class="claim-json" id="${id}-json">${esc(JSON.stringify(v, null, 2))}</div></td></tr>`
        : `<tr id="${id}"><td id="${id}-name">${esc(k)}</td><td id="${id}-value">${esc(v)}</td></tr>`;
    }).join("");
    claims.hidden = false;
    label.hidden = false;
  } else {
    claims.hidden = true;
    label.hidden = true;
  }
  renderPresentationLink(doc.presentation);
}

// The decoder link carries the complete presentation, because the wallet does
// not store it as a credential.
function renderPresentationLink(presentation) {
  const box = document.getElementById("presentation-box");
  const label = document.getElementById("presentation-label");
  if (!presentation) {
    box.hidden = true;
    label.hidden = true;
    return;
  }
  const link = document.getElementById("presentation-link");
  link.href = "../decoder/#credential=" + encodeURIComponent(presentation);
  box.hidden = false;
  label.hidden = false;
}

function schedulePoll(id) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(() => poll(id), pollDelay);
  pollDelay = Math.min(Math.round(pollDelay * 1.4), POLL_MAX);
}

function stopPolling() {
  clearTimeout(pollTimer);
  pollID = null;
}

// A poll that was in flight when the page created a newer request is stale. It
// must neither render nor schedule another poll.
async function poll(id) {
  if (id !== pollID) return;
  if (document.hidden) {
    schedulePoll(id);
    return;
  }
  try {
    const resp = await fetch("api/requests/" + id);
    if (id !== pollID) return;
    if (resp.status === 404) {
      renderResult({ status: "expired" });
      stopPolling();
      return;
    }
    if (!resp.ok) {
      schedulePoll(id);
      return;
    }
    const doc = await resp.json();
    if (id !== pollID) return;
    renderResult(doc);
    if (doc.status === "pending") {
      schedulePoll(id);
    } else {
      stopPolling();
    }
  } catch (e) {
    schedulePoll(id);
  }
}

function startPolling(id) {
  pollDelay = POLL_MIN;
  pollID = id;
  poll(id);
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && pollID) {
    pollDelay = POLL_MIN;
    clearTimeout(pollTimer);
    poll(pollID);
  }
});

// Only PID requests offer a format choice. The demo ticket is SD-JWT only.
const FORMAT_HINTS = {
  both: "The request asks for either format and the wallet answers with the one it holds.",
  "sd-jwt": "The request asks for the SD-JWT VC PID only. A wallet holding only the mdoc cannot answer it.",
  mdoc: "The request asks for the mdoc PID only. A wallet holding only the SD-JWT VC cannot answer it.",
};

// Both shapes use DCQL credential_sets (OpenID4VP 1.0 §6.2).
const TICKET_HINTS = {
  combined: "One option asks for the SD-JWT PID and the ticket together, the others for a PID alone.",
  optional: "A required set asks for a PID. A second set asks for the ticket, and the wallet may skip it.",
};

let pidFormat = "both";
let credential = "ticket";
let ticketMode = "combined";

for (const option of document.querySelectorAll("#credential-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    credential = option.dataset.credential;
    for (const other of document.querySelectorAll("#credential-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    const showsFormat = credential === "pid" || credential === "pid-de" || credential === "pid-ticket";
    document.getElementById("format-row").hidden = !showsFormat;
    document.getElementById("format-hint").hidden = !showsFormat;
    document.getElementById("ticket-row").hidden = credential !== "pid-ticket";
    document.getElementById("ticket-hint").hidden = credential !== "pid-ticket";
    // A custom request sets multiple per credential.
    document.getElementById("multiple-row").hidden = credential === "custom";
    document.getElementById("custom-panel").hidden = credential !== "custom";
  });
}

// The X.509 prefixes require a signed request object (OpenID4VP 1.0 §5.9).
const SCHEME_HINTS = {
  x509_hash: "The request object is signed and delivered behind request_uri.",
  x509_san_dns: "The request object is signed. The client id names a DNS SAN of the signing certificate, which must also match the response host.",
  redirect_uri: "The request is unsigned plain parameters. The client id binds to the response endpoint.",
  "pre-registered": "The request is unsigned plain parameters under a bare client id the wallet has no key for, so the wallet reports the signature as unverified.",
};

let clientIDScheme = "x509_hash";
for (const option of document.querySelectorAll("#scheme-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    clientIDScheme = option.dataset.scheme;
    for (const other of document.querySelectorAll("#scheme-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    document.getElementById("scheme-hint").textContent = SCHEME_HINTS[clientIDScheme];
    document.getElementById("client-id-row").hidden = clientIDScheme !== "pre-registered";
  });
}

function addClaimRow(container, value, id) {
  const row = document.createElement("div");
  row.className = "claim-row";
  row.id = id;
  const input = document.createElement("input");
  input.id = id + "-input";
  input.type = "text";
  input.className = "claim-input";
  input.placeholder = "given_name or nationalities[*]";
  input.value = value || "";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn icon small";
  remove.id = id + "-remove";
  remove.textContent = "×";
  remove.setAttribute("aria-label", "Remove claim");
  remove.addEventListener("click", () => row.remove());
  row.append(input, remove);
  container.append(row);
}

let credentialCount = 0;

function addCredential(seed) {
  const list = document.getElementById("credentials-list");
  const cred = document.createElement("div");
  cred.className = "cred";
  cred.id = "credentials-list-" + credentialCount++;
  let claimCount = 0;
  const nextClaimID = () => cred.id + "-claim-" + claimCount++;

  const head = document.createElement("div");
  head.className = "cred-head";
  head.id = cred.id + "-head";
  const toggle = document.createElement("div");
  toggle.className = "toggle format-select";
  toggle.id = cred.id + "-format";
  for (const fmt of ["dc+sd-jwt", "mso_mdoc"]) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "toggle-option" + (fmt === (seed?.format || "dc+sd-jwt") ? " selected" : "");
    b.dataset.format = fmt;
    b.id = toggle.id + "-" + idPart(fmt);
    b.textContent = fmt;
    b.addEventListener("click", () => {
      for (const other of toggle.children) other.classList.toggle("selected", other === b);
      typeInput.placeholder = b.dataset.format === "mso_mdoc" ? "doctype, e.g. eu.europa.ec.eudi.pid.1" : "vct, e.g. urn:eudi:pid:1";
    });
    toggle.append(b);
  }
  const typeInput = document.createElement("input");
  typeInput.type = "text";
  typeInput.className = "type-input";
  typeInput.id = cred.id + "-type";
  typeInput.placeholder = (seed?.format === "mso_mdoc") ? "doctype, e.g. eu.europa.ec.eudi.pid.1" : "vct, e.g. urn:eudi:pid:1";
  typeInput.value = seed?.type || "";
  const removeCred = document.createElement("button");
  removeCred.type = "button";
  removeCred.className = "btn icon small";
  removeCred.id = cred.id + "-remove";
  removeCred.textContent = "×";
  removeCred.setAttribute("aria-label", "Remove credential");
  removeCred.addEventListener("click", () => cred.remove());
  // OpenID4VP 1.0 §6.1 multiple: the wallet may answer with several credentials.
  const multipleLabel = document.createElement("label");
  multipleLabel.className = "multiple-option";
  multipleLabel.id = cred.id + "-multiple-label";
  const multiple = document.createElement("input");
  multiple.type = "checkbox";
  multiple.className = "multiple-input";
  multiple.id = cred.id + "-multiple";
  multiple.checked = !!seed?.multiple;
  multipleLabel.append(multiple, " multiple");
  head.append(toggle, typeInput, multipleLabel, removeCred);

  const claimsLabel = document.createElement("div");
  claimsLabel.className = "claims-label";
  claimsLabel.id = cred.id + "-claims-label";
  claimsLabel.textContent = "Claims";
  const claims = document.createElement("div");
  claims.className = "claims";
  claims.id = cred.id + "-claims";
  for (const c of seed?.claims || [""]) addClaimRow(claims, c, nextClaimID());
  const addClaim = document.createElement("button");
  addClaim.type = "button";
  addClaim.className = "btn small";
  addClaim.id = cred.id + "-add-claim";
  addClaim.textContent = "+ Claim";
  addClaim.addEventListener("click", () => addClaimRow(claims, "", nextClaimID()));

  cred.append(head, claimsLabel, claims, addClaim);
  list.append(cred);
}

document.getElementById("add-credential").addEventListener("click", () => addCredential());
addCredential({ format: "dc+sd-jwt", type: "urn:eudi:pid:1", claims: ["given_name", "nationalities"] });

function customRequestBody() {
  const credentials = [];
  for (const cred of document.querySelectorAll("#credentials-list .cred")) {
    const format = cred.querySelector(".format-select .selected").dataset.format;
    const type = cred.querySelector(".type-input").value.trim();
    const claims = [];
    for (const input of cred.querySelectorAll(".claim-input")) {
      const path = window.eudiParseClaimPath(input.value);
      if (path.length) claims.push(path);
    }
    const entry = { format, claims };
    if (cred.querySelector(".multiple-input").checked) entry.multiple = true;
    if (format === "mso_mdoc") entry.doctype = type;
    else entry.vct = type;
    credentials.push(entry);
  }
  const body = { type: "custom", client_id_scheme: clientIDScheme, credentials };
  if (clientIDScheme === "pre-registered") {
    const clientID = document.getElementById("client-id-input").value.trim();
    if (clientID) body.client_id = clientID;
  }
  return body;
}

document.getElementById("ticket-hint").textContent = TICKET_HINTS[ticketMode];
for (const option of document.querySelectorAll("#ticket-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    ticketMode = option.dataset.ticket;
    for (const other of document.querySelectorAll("#ticket-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    document.getElementById("ticket-hint").textContent = TICKET_HINTS[ticketMode];
  });
}

for (const option of document.querySelectorAll("#format-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    pidFormat = option.dataset.format;
    for (const other of document.querySelectorAll("#format-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    document.getElementById("format-hint").textContent = FORMAT_HINTS[pidFormat];
  });
}

const IDENTITY_HINTS = {
  registered: "The demo verifier is registered with the wallet's registrar for the credentials of the wallet's templates. The request is signed with its access certificate and carries its registration certificate. If the request asks for anything else, a wallet with ARF checks reports RPRC_21.",
  unregistered: "The request is signed with the demo verifier's access certificate but has no registration certificate. A wallet with ARF checks reports RPRC_19.",
  own: "The request is signed with your key and access certificate.",
  unsigned: "With this client identifier prefix the request is unsigned, so it can't show who the verifier is. The registration certificate and own certificates need x509_hash or x509_san_dns.",
};
let identity = "registered";
// chosenIdentity is the user's choice. An unsigned request shows
// "unregistered" without forgetting it.
let chosenIdentity = identity;

function selectIdentity(name) {
  identity = name;
  for (const other of document.querySelectorAll("#identity-toggle .toggle-option")) {
    const selected = other.dataset.identity === name;
    other.classList.toggle("selected", selected);
    other.setAttribute("aria-checked", String(selected));
  }
  document.getElementById("identity-hint").textContent = IDENTITY_HINTS[unsignedRequest() ? "unsigned" : identity];
  document.getElementById("identity-own-panel").hidden = identity !== "own";
}
for (const option of document.querySelectorAll("#identity-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    if (option.disabled) return;
    chosenIdentity = option.dataset.identity;
    selectIdentity(chosenIdentity);
  });
}
selectIdentity(identity);

// verifier_info needs a signed request (OpenID4VP 1.0 §5.1), so the custom
// redirect_uri and pre-registered schemes send no registration certificate.
function unsignedRequest() {
  return credential === "custom" && (clientIDScheme === "redirect_uri" || clientIDScheme === "pre-registered");
}
function updateIdentityAvailability() {
  const unsigned = unsignedRequest();
  for (const name of ["registered", "own"]) {
    const option = document.getElementById("identity-" + name);
    option.disabled = unsigned;
    option.title = unsigned ? "Needs a signed request (x509_hash or x509_san_dns)" : "";
  }
  selectIdentity(unsigned ? "unregistered" : chosenIdentity);
}
for (const id of ["credential-toggle", "scheme-toggle"]) {
  document.getElementById(id).addEventListener("click", updateIdentityAvailability);
}

function identityFields() {
  if (identity === "unregistered") return { identity: "unregistered" };
  if (identity !== "own") return {};
  const fields = {};
  const signingKey = document.getElementById("signing-key").value.trim();
  if (!signingKey) throw new Error("Paste the signing key and access certificate chain.");
  fields.signing_key = signingKey;
  const verifierInfo = document.getElementById("verifier-info").value.trim();
  if (verifierInfo) {
    try {
      fields.verifier_info = JSON.parse(verifierInfo);
    } catch (e) {
      throw new Error("verifier_info is not valid JSON: " + e.message);
    }
  }
  return fields;
}

document.getElementById("create-request").addEventListener("click", async () => {
  stopPolling();
  let request;
  if (credential === "custom") {
    request = customRequestBody();
  } else {
    request = { type: credential === "ticket" ? "ticket" : "pid" };
    if (credential !== "ticket") {
      request.format = pidFormat;
    }
    if (credential === "pid-de") {
      request.vct = "urn:eudi:pid:de:1";
    }
    if (credential === "pid-ticket") {
      request.ticket = ticketMode;
    }
    if (document.getElementById("request-multiple").checked) request.multiple = true;
  }
  try {
    Object.assign(request, identityFields());
  } catch (e) {
    renderResult({ status: "failed", error: e.message });
    return;
  }
  const resp = await fetch("api/requests", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  const doc = await resp.json();
  if (!resp.ok) {
    renderResult({ status: "failed", error: doc.error });
    return;
  }
  const link = document.getElementById("wallet-link");
  link.href = doc.wallet_url;
  link.textContent = doc.wallet_url;
  const scheme = document.getElementById("scheme-uri");
  scheme.textContent = doc.scheme_uri;
  scheme.href = doc.scheme_uri;
  document.getElementById("request-box").style.display = "block";
  renderResult({ status: "pending" });
  startPolling(doc.transaction_id);
  });

// The wallet redirects here with the response_code that reads the result
// (OpenID4VP 1.0 §8.2).
const responseCode = new URLSearchParams(location.search).get("response_code");
if (responseCode) startPolling(responseCode);

fetch("../api/config")
  .then((resp) => resp.json())
  .then((config) => {
    if (config.imprint) document.getElementById("imprint-link").hidden = false;
    if (config.demo && config.demo.enabled) document.getElementById("sponsor-info").hidden = false;
  })
  .catch(() => {});
