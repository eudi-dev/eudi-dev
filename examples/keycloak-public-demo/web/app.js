const REALM = `${CONFIG.keycloak}/realms/wallet-demo`;
const OIDC = `${REALM}/protocol/openid-connect`;
const LOGIN_CLIENT = "demo";
const CREDENTIAL = "demo-membership";
const REDIRECT_URI = `${location.origin}${location.pathname}`;

const $ = (id) => document.getElementById(id);

// A wallet in another tab ends the login in a new tab, so this has to outlive the starting tab.
const saveLogin = (state, login) => localStorage.setItem(`oidc-${state}`, JSON.stringify(login));

function takeLogin(state) {
  const key = `oidc-${state}`;
  const login = JSON.parse(localStorage.getItem(key) ?? "null");
  localStorage.removeItem(key);
  history.replaceState(null, "", location.pathname);
  if (!login) {
    throw new Error("This login started in another browser. Log in again here.");
  }
  return login;
}

const base64Url = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = () => base64Url(crypto.getRandomValues(new Uint8Array(32)));

async function signIn(flow, extra) {
  const verifier = random();
  const state = random();
  saveLogin(state, { verifier, flow });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const params = new URLSearchParams({
    client_id: LOGIN_CLIENT,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    state,
    code_challenge: base64Url(new Uint8Array(digest)),
    code_challenge_method: "S256",
    // An earlier step of the demo leaves a session, and each step has to sign in again.
    prompt: "login",
    ...extra,
  });
  location.assign(`${OIDC}/auth?${params}`);
}

async function request(url, options) {
  try {
    return await fetch(url, options);
  } catch {
    throw new Error("Keycloak could not be reached. Try again in a minute.");
  }
}

async function redeemCode(params) {
  const stored = takeLogin(params.get("state"));
  const response = await request(`${OIDC}/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: LOGIN_CLIENT,
      code: params.get("code"),
      redirect_uri: REDIRECT_URI,
      code_verifier: stored.verifier,
    }),
  });
  if (!response.ok) {
    throw new Error(`Token request failed: ${await response.text()}`);
  }
  return { flow: stored.flow, tokens: await response.json() };
}

function offerAction(kind) {
  const config = {
    credentialConfigurationId: CREDENTIAL,
    preAuthorized: kind === "pre-authorized",
    clientId: CONFIG.walletClient,
  };
  return `verifiable_credential_offer:${base64Url(new TextEncoder().encode(JSON.stringify(config)))}`;
}

function showClaims(idToken) {
  const payload = idToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  const claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload), (c) => c.charCodeAt(0))));
  const { name, email, sub } = claims;
  const rows = Object.entries({ Name: name, Email: email, Subject: sub }).map(([label, value]) => {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const detail = document.createElement("code");
    term.textContent = label;
    detail.textContent = value;
    row.append(term, detail);
    return row;
  });
  $("claims").replaceChildren(...rows);
  $("claims").hidden = false;
  $("step-login").classList.add("done");
}

async function copy(button, text) {
  const label = button.textContent;
  await navigator.clipboard.writeText(text);
  button.textContent = "Copied";
  setTimeout(() => { button.textContent = label; }, 1200);
}

function selectOffer(kind) {
  document.querySelectorAll("[data-offer]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.offer === kind));
  });
}

function selectedOffer() {
  return document.querySelector('[data-offer][aria-pressed="true"]').dataset.offer;
}

// A deployment with variants publishes this list at the site root.
async function showVariants() {
  const response = await fetch("/variants.json").catch(() => null);
  if (!response?.ok) return;
  const variants = await response.json();
  if (variants.length < 2) return;
  const select = $("variants");
  select.replaceChildren(...variants.map(({ path, label }) => new Option(label, path)));
  select.value = location.pathname;
  select.hidden = false;
  select.addEventListener("change", () => location.assign(select.value));
}

// The browser blocks a window opened after an await, so it opens first.
async function openInDecoder(source) {
  const decoder = window.open("", "_blank");
  try {
    const response = await fetch(source);
    if (!response.ok) throw new Error(`The list answered ${response.status}`);
    decoder.location = `${CONFIG.wallet}/decoder/#credential=${encodeURIComponent((await response.text()).trim())}`;
  } catch (error) {
    decoder.close();
    fail(error);
  }
}

function trustRow({ name, description, publisher, url, source }) {
  const row = document.createElement("div");
  row.className = "trust-row";
  const label = document.createElement("div");
  const link = Object.assign(document.createElement("a"), { href: url, target: "_blank", rel: "noopener", textContent: name, title: url });
  const origin = Object.assign(document.createElement("span"), { textContent: `From ${publisher}, ` });
  origin.append(Object.assign(document.createElement("code"), { textContent: new URL(url).host }));
  label.append(link, Object.assign(document.createElement("span"), { textContent: description }), origin);
  const menu = document.createElement("details");
  menu.className = "trust-list-menu";
  const toggle = Object.assign(document.createElement("summary"), { className: "btn btn-sm", textContent: "Actions" });
  const items = Object.assign(document.createElement("div"), { className: "trust-list-menu-items" });
  const addItem = (text, run) => {
    const item = Object.assign(document.createElement("button"), { type: "button", textContent: text });
    item.addEventListener("click", () => {
      menu.open = false;
      run();
    });
    items.append(item);
  };
  addItem("Copy URL", async () => {
    await navigator.clipboard.writeText(url);
    toggle.textContent = "Copied!";
    setTimeout(() => { toggle.textContent = "Actions"; }, 2000);
  });
  if (source) addItem("Open in decoder", () => openInDecoder(source));
  menu.append(toggle, items);
  row.append(label, menu);
  return row;
}

function setUpTrustDialog() {
  const issuer = new URL(REALM);
  $("trust-lists").replaceChildren(...[
    {
      name: "Demo issuers",
      description: "Issuers Keycloak accepts at the wallet login",
      publisher: "this demo's setup",
      url: new URL("trust-lists/issuers.jwt", location.href).href,
      source: "trust-lists/issuers.jwt",
    },
    {
      name: "Wallet providers",
      description: "Wallet providers Keycloak accepts in key and wallet attestations",
      publisher: "the wallet",
      url: `${CONFIG.wallet}/api/trustlists/wallet-provider`,
      source: `${CONFIG.wallet}/api/trustlists/wallet-provider`,
    },
  ].map(trustRow));
  $("trust-issuer").replaceChildren(...[
    { name: "Issuer metadata", description: "OpenID4VCI", publisher: "Keycloak", url: `${issuer.origin}/.well-known/openid-credential-issuer${issuer.pathname}` },
    { name: "Signing keys", description: "JWKS of the realm", publisher: "Keycloak", url: `${OIDC}/certs` },
  ].map(trustRow));
  $("trust-hint").textContent = CONFIG.trust === "etsi-trust-list"
    ? "Keycloak fetches these lists (ETSI TS 119 602)."
    : "This Keycloak cannot read these lists, so setup gave it their certificates.";
  document.querySelectorAll("[data-open-trust]").forEach((link) => {
    link.hidden = CONFIG.trust === "none";
    link.addEventListener("click", (event) => {
      event.preventDefault();
      $("trust-dialog").showModal();
    });
  });
  $("trust-close").addEventListener("click", () => $("trust-dialog").close());
}

function fail(error) {
  $("error").textContent = error.message;
  $("error").hidden = false;
}

function setUpPage() {
  $("wallet-link").href = CONFIG.wallet;
  $("footer-version").textContent = `Keycloak ${CONFIG.keycloakVersion}`;
  if (CONFIG.imprint) {
    $("imprint-link").href = CONFIG.imprint;
    $("imprint-link").hidden = false;
  }
  $("console").href = `${CONFIG.keycloak}/admin/wallet-demo/console/`;
  $("master-console").href = `${CONFIG.keycloak}/admin/master/console/`;
  $("step-login").hidden = !CONFIG.walletLogin;
  document.querySelectorAll(".demo-user").forEach((element) => { element.textContent = CONFIG.demoUser; });
  document.querySelectorAll("[data-offer]").forEach((button) => {
    button.addEventListener("click", () => selectOffer(button.dataset.offer));
  });
  document.querySelectorAll("[data-copy-from]").forEach((button) => {
    button.addEventListener("click", () => copy(button, document.querySelector(button.dataset.copyFrom).textContent));
  });
  $("issue").addEventListener("click", () => {
    signIn(selectedOffer(), { kc_action: offerAction(selectedOffer()) });
  });
  $("login").addEventListener("click", () => signIn("login", { kc_idp_hint: "oid4vp" }));
}

(async () => {
  setUpPage();
  setUpTrustDialog();
  showVariants();
  const params = new URLSearchParams(location.search);
  if (params.has("error")) {
    history.replaceState(null, "", location.pathname);
    // Keycloak reports this when the wallet finished the login in another tab.
    if (params.get("error") === "authentication_expired") {
      throw new Error("The login finished in another tab. Start it again here to see the result.");
    }
    throw new Error(params.get("error_description") ?? params.get("error"));
  }
  if (params.has("code")) {
    const finished = params.get("kc_action_status") === "success";
    const { flow, tokens } = await redeemCode(params);
    if (flow === "login") {
      showClaims(tokens.id_token);
    } else {
      selectOffer(flow);
      $("step-issue").classList.toggle("done", finished);
    }
  }
})().catch(fail);
