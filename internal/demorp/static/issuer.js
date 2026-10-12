async function createOffer(grant, status, authorization, deferred, batch, credential) {
  const errEl = document.getElementById("error");
  errEl.hidden = true;
  try {
    const params = new URLSearchParams();
    if (grant) params.set("grant", grant);
    if (status) params.set("status", status);
    if (deferred) params.set("deferred", "true");
    if (batch) params.set("batch", batch);
    if (credential) params.set("credential", credential);
    if (grant && authorization) params.set("authorization", authorization);
    const query = params.toString() ? "?" + params.toString() : "";
    const resp = await fetch("api/offers" + query, { method: "POST" });
    const doc = await resp.json();
    if (!resp.ok) throw new Error(doc.error || resp.status);
    const link = document.getElementById("wallet-link");
    link.href = doc.wallet_url;
    link.textContent = doc.wallet_url;
    const scheme = document.getElementById("scheme-uri");
    scheme.textContent = doc.scheme_uri;
    scheme.href = doc.scheme_uri;
    document.getElementById("offer-uri").textContent = doc.offer_uri;
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

const AUTHORIZATION_HINTS = {
  browser: "Sign in here as alice (password alice).",
  presentation: "The wallet presents a PID before the issuer issues (OpenID4VCI 1.1 interactive authorization).",
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
let status = "";
let authorization = "browser";
let deferred = "";
let batch = "";
let credential = "";

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
});
bindToggle("authorization-toggle", "authorization", "authorization-hint", AUTHORIZATION_HINTS, (value) => {
  authorization = value;
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

document.getElementById("create-btn")
  .addEventListener("click", () => createOffer(grant, status, authorization, deferred, batch, credential));

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
    if (config.status_list_url) {
      document.getElementById("status-row").hidden = false;
      document.getElementById("status-hint").hidden = false;
    }
  })
  .catch(() => {});
