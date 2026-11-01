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

// The wallet's client authenticates with an attestation only the wallet has, so the page signs in
// as that client with the implicit flow, which needs no client authentication.
function signInAsWallet(flow) {
  const state = random();
  saveLogin(state, { flow });
  const params = new URLSearchParams({
    client_id: CONFIG.walletClient,
    redirect_uri: REDIRECT_URI,
    response_type: "token",
    scope: "openid",
    state,
    prompt: "login",
  });
  location.assign(`${OIDC}/auth?${params}`);
}

function readToken(fragment) {
  const { flow } = takeLogin(fragment.get("state"));
  return { flow, tokens: { access_token: fragment.get("access_token") } };
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

async function showOffer(kind, accessToken) {
  selectOffer(kind);
  const query = new URLSearchParams({
    credential_configuration_id: CREDENTIAL,
    pre_authorized: String(kind === "pre-authorized"),
    type: "uri_qr",
    width: "200",
    height: "200",
  });
  const response = await request(`${REALM}/protocol/oid4vc/create-credential-offer?${query}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new Error(`Creating the offer failed: ${await response.text()}`);
  }
  const offer = await response.json();
  const offerUri = `${offer.issuer}/${offer.nonce}`;
  const parameter = `credential_offer_uri=${encodeURIComponent(offerUri)}`;
  $("offer-link").href = `${CONFIG.wallet}/credential-offer?${parameter}`;
  $("offer-qr").src = offer.qr_code;
  $("offer-copy").onclick = (event) => copy(event.target, `openid-credential-offer://?${parameter}`);
  $("offer").hidden = false;
  $("step-issue").classList.add("done");
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
    button.addEventListener("click", () => {
      selectOffer(button.dataset.offer);
      $("offer").hidden = true;
      $("step-issue").classList.remove("done");
    });
  });
  document.querySelectorAll("[data-copy-from]").forEach((button) => {
    button.addEventListener("click", () => copy(button, document.querySelector(button.dataset.copyFrom).textContent));
  });
  $("issue").addEventListener("click", () => {
    // A pre-authorized offer is bound to the client that creates it, and the wallet redeems it as itself.
    if (selectedOffer() === "pre-authorized") signInAsWallet("pre-authorized");
    else signIn("authorization-code");
  });
  $("login").addEventListener("click", () => signIn("login", { kc_idp_hint: "oid4vp" }));
}

(async () => {
  setUpPage();
  showVariants();
  const fragment = new URLSearchParams(location.hash.slice(1));
  const params = new URLSearchParams(location.search);
  const failure = fragment.has("error") ? fragment : params;
  if (failure.has("error")) {
    history.replaceState(null, "", location.pathname);
    // Keycloak reports this when the wallet finished the login in another tab.
    if (failure.get("error") === "authentication_expired") {
      throw new Error("The login finished in another tab. Start it again here to see the result.");
    }
    throw new Error(failure.get("error_description") ?? failure.get("error"));
  }
  if (fragment.has("access_token")) {
    const { flow, tokens } = readToken(fragment);
    await showOffer(flow, tokens.access_token);
  } else if (params.has("code")) {
    const { flow, tokens } = await redeemCode(params);
    if (flow === "login") {
      showClaims(tokens.id_token);
    } else {
      await showOffer(flow, tokens.access_token);
    }
  }
})().catch(fail);
