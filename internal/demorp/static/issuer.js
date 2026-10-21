async function createOffer(grant, txCode, status, authorization, deferred, batch, proofTypes, credential, identity, identityCheck) {
  const errEl = document.getElementById("error");
  errEl.hidden = true;
  try {
    const init = { method: "POST" };
    const params = new URLSearchParams();
    const body = {};
    if (identity !== "registered") params.set("identity", identity);
    if (identity === "own") Object.assign(body, ownIdentityBody());
    if (identityCheckShown() && identityCheck !== "registered") {
      params.set("identity_check", identityCheck);
      if (identityCheck === "own") body.identity_check = ownIdentityCheckBody();
    }
    if (Object.keys(body).length) {
      init.headers = { "Content-Type": "application/json" };
      init.body = JSON.stringify(body);
    }
    if (grant) params.set("grant", grant);
    else if (txCode) params.set("tx_code", "true");
    if (status) params.set("status", status);
    if (deferred) params.set("deferred", "true");
    if (batch) params.set("batch", batch);
    if (proofTypes) params.set("proof_types", proofTypes);
    if (credential) params.set("credential", credential);
    if (grant && authorization) params.set("authorization", authorization);
    const query = params.toString() ? "?" + params.toString() : "";
    const resp = await fetch("api/offers" + query, init);
    const doc = await resp.json();
    if (!resp.ok) throw new Error(doc.error_description || doc.error || resp.status);
    const link = document.getElementById("wallet-link");
    link.href = doc.wallet_url;
    link.textContent = doc.wallet_url;
    const scheme = document.getElementById("scheme-uri");
    scheme.textContent = doc.scheme_uri;
    scheme.href = doc.scheme_uri;
    showQR("wallet-link-qr", doc.wallet_url_qr);
    showQR("scheme-uri-qr", doc.scheme_uri_qr);
    document.getElementById("tx-code-result").hidden = !doc.tx_code;
    document.getElementById("tx-code-value").textContent = doc.tx_code || "";
    document.getElementById("offer-uri").textContent = doc.offer_uri;
    document.getElementById("issuer-id").textContent = doc.issuer;
    document.getElementById("result").style.display = "block";
  } catch (e) {
    errEl.textContent = "Creating the offer failed: " + e.message;
    errEl.hidden = false;
  }
}

const GRANT_HINTS = {
  "": "The offer carries the code. No sign-in.",
  authorization_code: "The wallet uses PAR, PKCE, DPoP and a wallet attestation.",
};

const TX_CODE_HINTS = {
  "": "No code to enter in the wallet.",
  true: "The user enters a six-digit code in the wallet. It appears below the offer.",
};

const AUTHORIZATION_HINTS = {
  browser: "Sign in here as alice (password alice).",
  presentation: "The wallet presents a PID before issuance (OpenID4VCI 1.1 interactive authorization).",
};

// Credentials need a status reference before the wallet can revoke them.
const STATUS_HINTS = {
  "": "No status reference. The ticket can't be revoked.",
  true: "On this wallet's status list. Revoke it in the wallet to test the demo verifier.",
};

const DEFERRED_HINTS = {
  "": "Issued at once.",
  true: "Issued a few seconds later at the deferred credential endpoint (OpenID4VCI 1.0 §9).",
};

const PROOF_TYPES_HINTS = {
  "": "The wallet chooses. The attestation proof type needs a key attestation from the wallet provider.",
  jwt: "The metadata lists only the jwt proof type. The offer gets an issuer identifier of its own.",
};

const IDENTITY_HINTS = {
  registered: "The metadata is signed with the demo issuer's access certificate and carries its registration certificate in issuer_info.",
  unregistered: "The metadata has no issuer_info. A wallet with ARF checks warns about the missing registration certificate (RPRC_22a).",
  unsigned: "The metadata is plain JSON, even when the wallet asks for signed metadata. It has no issuer_info and no access certificate.",
  own: "The metadata is signed with your key and access certificate and carries your issuer_info. The offer gets an issuer identifier of its own.",
};

// A server started with --demo-issuer-signing-key signs with that certificate.
if (document.body.dataset.configuredIdentity) {
  IDENTITY_HINTS.registered = "The metadata is signed with the access certificate the server was started with and carries the issuer_info given with it.";
  IDENTITY_HINTS.unregistered = "The metadata is signed with the access certificate the server was started with and has no issuer_info. A wallet with ARF checks warns about the missing registration certificate (RPRC_22a).";
  document.getElementById("identity-hint").textContent = IDENTITY_HINTS.registered;
}

const IDENTITY_CHECK_HINTS = {
  registered: "The PID request is signed with the demo issuer's access certificate and carries the registration certificate of the identity check in verifier_info.",
  unregistered: "The PID request has no verifier_info. A wallet with ARF checks warns about the missing registration certificate (RPRC_19).",
  own: "The PID request is signed with your key and access certificate and carries your verifier_info.",
};

// ownMaterial reads a pasted key with its certificates and an optional JSON
// value, such as issuer_info, from two text areas.
function ownMaterial(keyID, infoID, infoName) {
  const signingKey = document.getElementById(keyID).value.trim();
  if (!signingKey) throw new Error("paste the signing key and access certificate chain");
  const body = { signing_key: signingKey };
  const info = document.getElementById(infoID).value.trim();
  if (info) {
    try {
      body[infoName] = JSON.parse(info);
    } catch (e) {
      throw new Error(infoName + " is not valid JSON: " + e.message);
    }
  }
  return body;
}

// ownIdentityBody reads the key, the certificates and issuer_info of an own identity.
function ownIdentityBody() {
  return ownMaterial("signing-key", "issuer-info", "issuer_info");
}

// ownIdentityCheckBody reads the key, the certificates and verifier_info of an
// own identity check.
function ownIdentityCheckBody() {
  return ownMaterial("identity-check-signing-key", "identity-check-verifier-info", "verifier_info");
}

function batchHint(n) {
  return n + " copies, each on its own key (OpenID4VCI 1.0 §8.3). Each presentation uses an unused copy.";
}
const BATCH_HINTS = {
  "": "One credential.",
  2: batchHint(2),
  3: batchHint(3),
  5: batchHint(5),
};

let grant = "";
let txCode = "";
let status = document.querySelector("#status-toggle .selected")?.dataset.status || "";
let authorization = "browser";
let deferred = "";
let batch = "";
let proofTypes = "";
let credential = "";
let identity = "registered";
let identityCheck = "registered";

// The identity check is the PID presentation of interactive authorization.
function identityCheckShown() {
  return grant === "authorization_code" && authorization === "presentation";
}

function updateIdentityCheck() {
  const shown = identityCheckShown();
  document.getElementById("identity-check-row").hidden = !shown;
  document.getElementById("identity-check-hint").hidden = !shown;
  document.getElementById("identity-check-own-panel").hidden = !shown || identityCheck !== "own";
}

function bindToggle(id, key, hintID, hints, onChange) {
  const group = document.getElementById(id);
  if (!group) return;
  for (const option of group.querySelectorAll(".toggle-option")) {
    option.addEventListener("click", () => {
      onChange(option.dataset[key] || "");
      for (const other of group.querySelectorAll(".toggle-option")) {
        const selected = other === option;
        other.classList.toggle("selected", selected);
        other.setAttribute("aria-checked", String(selected));
      }
      document.getElementById(hintID).textContent = hints[option.dataset[key] || ""];
      // Clear the old offer when its settings change.
      document.getElementById("result").style.display = "none";
    });
  }
}

bindToggle("grant-toggle", "grant", "grant-hint", GRANT_HINTS, (value) => {
  grant = value;
  const shown = value === "authorization_code";
  document.getElementById("authorization-row").hidden = !shown;
  document.getElementById("authorization-hint").hidden = !shown;
  // A transaction code protects only a pre-authorized code.
  document.getElementById("tx-code-row").hidden = shown;
  document.getElementById("tx-code-hint").hidden = shown;
  updateIdentityCheck();
});
bindToggle("tx-code-toggle", "txCode", "tx-code-hint", TX_CODE_HINTS, (value) => {
  txCode = value;
});
bindToggle("authorization-toggle", "authorization", "authorization-hint", AUTHORIZATION_HINTS, (value) => {
  authorization = value;
  updateIdentityCheck();
});
bindToggle("identity-check-toggle", "identityCheck", "identity-check-hint", IDENTITY_CHECK_HINTS, (value) => {
  identityCheck = value;
  updateIdentityCheck();
});
bindToggle("status-toggle", "status", "status-hint", STATUS_HINTS, (value) => {
  status = value;
});
bindToggle("deferred-toggle", "deferred", "deferred-hint", DEFERRED_HINTS, (value) => {
  deferred = value;
});
bindToggle("batch-toggle", "batch", "batch-hint", BATCH_HINTS, (value) => {
  batch = value;
});
bindToggle("proof-types-toggle", "proofTypes", "proof-types-hint", PROOF_TYPES_HINTS, (value) => {
  proofTypes = value;
});
bindToggle("identity-toggle", "identity", "identity-hint", IDENTITY_HINTS, (value) => {
  identity = value;
  document.getElementById("identity-own-panel").hidden = value !== "own";
});

document.getElementById("create-btn")
  .addEventListener("click", () => createOffer(grant, txCode, status, authorization, deferred, batch, proofTypes, credential, identity, identityCheck));

const credentialSelect = document.getElementById("credential-select");
credentialSelect.addEventListener("change", () => {
  credential = credentialSelect.value;
  document.getElementById("result").style.display = "none";
});

// The page offers the configurations from the issuer metadata (the ticket and
// one per template) and labels them the way a wallet would.
fetch(".well-known/openid-credential-issuer")
  .then((resp) => resp.json())
  .then((metadata) => {
    const configurations = metadata.credential_configurations_supported || {};
    for (const id of Object.keys(configurations).sort()) {
      if (id === "demo-ticket") continue;
      const entry = configurations[id];
      const display = ((entry.credential_metadata || {}).display || [])[0] || {};
      const option = document.createElement("option");
      option.value = id;
      option.textContent = (display.name || id) + " (" + id + ", " + entry.format + ")";
      credentialSelect.appendChild(option);
    }
  })
  .catch(() => {});

fetch("../api/config")
  .then((resp) => resp.json())
  .then((config) => {
    window.eudiFooter(config);
  })
  .catch(() => {});
