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

function sentence(s) {
  s = String(s || "");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Check names are plain words or start with a protocol name such as vp_token.
// Only plain words take a capital letter.
function checkName(name) {
  const label = name.lastIndexOf(": ");
  const prefix = label >= 0 ? name.slice(0, label + 2) : "";
  const rest = name.slice(prefix.length);
  if (rest === "haip") return prefix + "HAIP";
  return prefix + (/^[a-z]+(\s|$)/.test(rest) ? sentence(rest) : rest);
}

function checkItem(c, i) {
  // A protocol check can pass while reporting a profile warning.
  let kind = c.ok ? "ok" : "fail";
  let detail = c.error || c.detail || "";
  if (c.ok && c.warning) {
    kind = "warn";
    detail = c.warning;
  } else if (c.ok && c.skipped) {
    kind = "skip";
    detail = c.skipped;
  }
  // A passing type check names the typ value, which keeps its case.
  if (!(kind === "ok" && /(^|: )type$/.test(c.name))) detail = sentence(detail);
  // The group heading shows the credential, so the name drops it.
  const group = c.credential || "";
  const name = group && c.name.startsWith(group + ": ") ? c.name.slice(group.length + 2) : c.name;
  return { id: "checks-" + i, kind, name: checkName(name), detail, group };
}

const CHECK_ICONS = { ok: "✓", fail: "✗", warn: "!", skip: "–" };

function checkHTML(it) {
  const detail = it.detail ? `<span class="check-detail" id="${it.id}-detail">: ${esc(it.detail)}</span>` : "";
  return `<div class="check-item ${it.kind}" id="${it.id}"><span class="check-icon">${CHECK_ICONS[it.kind]}</span><span class="check-text"><span id="${it.id}-name">${esc(it.name)}</span>${detail}</span></div>`;
}

// A response with several credentials lists the checks of each one under its
// query id. Checks of the whole response come first.
function groupedHTML(items, idPrefix) {
  const groups = [...new Set(items.map((it) => it.group))];
  if (groups.length < 2 && !groups[0]) return items.map(checkHTML).join("");
  return groups.map((g) => {
    const head = g ? `<div class="check-group" id="${idPrefix}-${idPart(g)}">${esc(g)}</div>` : "";
    return head + items.filter((it) => it.group === g).map(checkHTML).join("");
  }).join("");
}

let lastRendered = "";

function renderResult(doc) {
  // Polling continues while the request stays open. An unchanged result keeps
  // the page as it is, with the passed checks opened or closed.
  const rendered = JSON.stringify(doc);
  if (rendered === lastRendered) return;
  lastRendered = rendered;
  const box = document.getElementById("result-box");
  box.style.display = "block";
  const items = (doc.checks || []).map(checkItem);
  const passed = items.filter((it) => it.kind === "ok");
  const warnings = items.filter((it) => it.kind === "warn");
  const status = document.getElementById("status");
  status.className = "status " + doc.status;
  if (doc.status === "verified") {
    let text = "✓ Presentation verified, " + passed.length + (passed.length === 1 ? " check passed" : " checks passed");
    if (warnings.length) text += ", " + warnings.length + (warnings.length === 1 ? " warning" : " warnings");
    status.textContent = text;
  } else if (doc.status === "failed") {
    status.innerHTML = "✗ Verification failed" + (doc.error ? `<div class="check-detail" id="status-error">${esc(sentence(doc.error))}</div>` : "");
  } else if (doc.status === "declined") {
    status.innerHTML = `✗ The wallet declined: <span id="status-error">${esc(doc.error || "")}</span>`;
  } else {
    status.textContent = doc.status === "expired" ? "Request expired, create a new one" : "Waiting for the wallet…";
  }
  const checks = document.getElementById("checks");
  const wasOpen = document.getElementById("checks-passed")?.open;
  const shown = groupedHTML(items.filter((it) => it.kind !== "ok"), "checks-group-shown");
  checks.innerHTML = shown + (passed.length
    ? `<details id="checks-passed"${wasOpen ? " open" : ""}><summary id="checks-passed-summary">${passed.length === 1 ? "1 check passed" : passed.length + " checks passed"}</summary>${groupedHTML(passed, "checks-group")}</details>`
    : "");
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
    restoreSelection(doc.request);
    renderResult(doc);
    if (doc.status === "pending" || doc.open) {
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
  both: "The wallet answers in either format.",
  "sd-jwt": "Only an SD-JWT VC PID matches.",
  mdoc: "Only an mdoc PID matches.",
};

// Both shapes use DCQL credential_sets (OpenID4VP 1.0 §6.2).
const TICKET_HINTS = {
  combined: "One option asks for the SD-JWT PID with the ticket. The others ask for a PID alone.",
  optional: "The PID is required. The ticket is an optional second credential set.",
};

let pidFormat = "both";
let credential = "ticket";
// vct is the national PID type of the selected option.
let vct = "";
let ticketMode = "combined";

// markSelected marks the options of a toggle group that isSelected accepts.
function markSelected(id, isSelected) {
  for (const option of document.querySelectorAll(`#${id} .toggle-option`)) {
    const selected = isSelected(option);
    option.classList.toggle("selected", selected);
    option.setAttribute("aria-checked", String(selected));
  }
}

// bindToggle selects a clicked option of the group and hands it to onSelect.
function bindToggle(id, onSelect) {
  for (const option of document.querySelectorAll(`#${id} .toggle-option`)) {
    option.addEventListener("click", () => {
      if (option.disabled) return;
      markSelected(id, (other) => other === option);
      onSelect(option);
    });
  }
}

bindToggle("credential-toggle", (option) => {
  credential = option.dataset.credential;
  vct = option.dataset.vct || "";
  const showsFormat = credential === "pid" || vct !== "" || credential === "pid-ticket";
  document.getElementById("format-row").hidden = !showsFormat;
  document.getElementById("format-hint").hidden = !showsFormat;
  document.getElementById("ticket-row").hidden = credential !== "pid-ticket";
  document.getElementById("ticket-hint").hidden = credential !== "pid-ticket";
  // A custom request sets multiple per credential.
  document.getElementById("multiple-row").hidden = credential === "custom";
  document.getElementById("custom-panel").hidden = credential !== "custom";
});

// The X.509 prefixes require a signed request object (OpenID4VP 1.0 §5.9).
const SCHEME_HINTS = {
  x509_hash: "Signed request object behind request_uri.",
  x509_san_dns: "Signed request object. The client id is a DNS name of the certificate and must match the response host.",
  redirect_uri: "Unsigned request. The client id is the response endpoint.",
  "pre-registered": "Unsigned request with a bare client id. The wallet reports the signature as unverified.",
};

let clientIDScheme = "x509_hash";
bindToggle("scheme-toggle", (option) => {
  clientIDScheme = option.dataset.scheme;
  document.getElementById("scheme-hint").textContent = SCHEME_HINTS[clientIDScheme];
  document.getElementById("client-id-row").hidden = clientIDScheme !== "pre-registered";
});

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
  multipleLabel.title = "DCQL multiple (OpenID4VP 1.0 §6.1)";
  multipleLabel.append(multiple, " Several");
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
bindToggle("ticket-toggle", (option) => {
  ticketMode = option.dataset.ticket;
  document.getElementById("ticket-hint").textContent = TICKET_HINTS[ticketMode];
});

bindToggle("format-toggle", (option) => {
  pidFormat = option.dataset.format;
  document.getElementById("format-hint").textContent = FORMAT_HINTS[pidFormat];
});

const IDENTITY_HINTS = {
  registered: "Signed with the demo verifier's access certificate and sent with its registration certificate.",
  unregistered: "No registration certificate. A wallet with ARF checks reports RPRC_19.",
  own: "Signed with your key and access certificate.",
  unsigned: "Needs a signed request object (x509_hash or x509_san_dns).",
};
let identity = "registered";
// chosenIdentity is the user's choice. An unsigned request shows
// "unregistered" without forgetting it.
let chosenIdentity = identity;

function selectIdentity(name) {
  identity = name;
  markSelected("identity-toggle", (option) => option.dataset.identity === name);
  document.getElementById("identity-hint").textContent = IDENTITY_HINTS[unsignedRequest() ? "unsigned" : identity];
  document.getElementById("identity-own-panel").hidden = identity !== "own";
}
bindToggle("identity-toggle", (option) => {
  chosenIdentity = option.dataset.identity;
  selectIdentity(chosenIdentity);
});
selectIdentity(identity);

// verifier_info needs a signed request object (OpenID4VP 1.0 §5.1), so the custom
// redirect_uri and pre-registered schemes send no registration certificate.
function unsignedRequest() {
  return credential === "custom" && (clientIDScheme === "redirect_uri" || clientIDScheme === "pre-registered");
}
function updateIdentityAvailability() {
  const unsigned = unsignedRequest();
  for (const name of ["registered", "own"]) {
    const option = document.getElementById("identity-" + name);
    option.disabled = unsigned;
    option.title = unsigned ? "Needs a signed request object (x509_hash or x509_san_dns)" : "";
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
    if (vct) {
      request.vct = vct;
    }
    if (credential !== "ticket") {
      request.format = pidFormat;
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

// The redirect opens a fresh page. The controls show the request it answers.
let selectionRestored = !responseCode;
function restoreSelection(request) {
  if (selectionRestored || !request) return;
  selectionRestored = true;
  let option = "ticket";
  if (request.type === "custom") option = "custom";
  else if (request.type === "pid" && request.ticket) option = "pid-ticket";
  else if (request.type === "pid") option = "pid";
  const national = request.vct && document.querySelector(`#credential-toggle [data-vct="${CSS.escape(request.vct)}"]`);
  const button = national || document.querySelector(`#credential-toggle [data-credential="${option}"]`);
  if (button) button.click();
  if (request.format) document.querySelector(`#format-toggle [data-format="${CSS.escape(request.format)}"]`)?.click();
  if (request.ticket) document.querySelector(`#ticket-toggle [data-ticket="${CSS.escape(request.ticket)}"]`)?.click();
  document.getElementById("request-multiple").checked = !!request.multiple;
}
if (responseCode) startPolling(responseCode);

fetch("../api/config")
  .then((resp) => resp.json())
  .then(window.eudiFooter)
  .catch(() => {});
