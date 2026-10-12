(() => {
  "use strict";

  // The decoder may be mounted below /decoder/, so API paths are relative.
  const basePath = (() => {
    const path = window.location.pathname;
    return path.endsWith("/") ? path : path.substring(0, path.lastIndexOf("/") + 1);
  })();

  const input = document.getElementById("input");
  const outputEl = document.getElementById("output");
  const formatBadge = document.getElementById("format-badge");
  const clearBtn = document.getElementById("clear-btn");
  const shareBtn = document.getElementById("share-btn");
  const rawView = document.getElementById("raw-view");
  const EMPTY_OUTPUT_HTML = '<div class="placeholder" id="output-placeholder">Paste a credential to see decoded output</div>';

  let decodeTimer = null;
  let decodeDueAt = 0;
  // Ignore results from earlier decodes after the input changes.
  let decodeSeq = 0;
  let renderedSeq = -1;
  let lastData = null;
  let lastValidation = null;
  let colorized = false;
  let usedIds = new Set();
  // The wallet credential ID stays while the content is unchanged, so shared links can use
  // the short form.
  let walletCredential = null;

  const DISC_COLORS = 8;

  const TIMESTAMP_FIELDS = new Set(["exp", "iat", "nbf", "auth_time", "updated_at"]);

  clearBtn.addEventListener("click", () => {
    input.value = "";
    resetOutput();
    history.replaceState(null, "", window.location.pathname);
    input.focus();
  });

  shareBtn.addEventListener("click", copyShareLink);

  function copyShareLink() {
    const text = input.value.trim();
    if (!text) return;
    const url = window.location.origin + buildCredentialURL(text);
    navigator.clipboard.writeText(url).then(() => {
      showToast("Link copied to clipboard");
    }).catch(() => {
      showToast("Failed to copy link");
    });
  }

  function resetOutput() {
    outputEl.innerHTML = EMPTY_OUTPUT_HTML;
    formatBadge.className = "badge hidden";
    lastData = null;
    lastValidation = null;
    renderedSeq = -1;
    hideColorized();
  }

  function buildCredentialURL(text) {
    if (!text) return window.location.pathname;
    if (walletCredential && walletCredential.credential === text) {
      return window.location.pathname + "?id=" + encodeURIComponent(walletCredential.id);
    }
    // The fragment never reaches the server, so a proxy's URL length limit
    // doesn't cut off a long credential or request object.
    return window.location.pathname + "#credential=" + encodeURIComponent(text);
  }

  // linkedCredential reads a credential from the fragment or, for older links,
  // from the query.
  function linkedCredential() {
    const fromHash = new URLSearchParams(window.location.hash.slice(1)).get("credential");
    return fromHash || new URLSearchParams(window.location.search).get("credential") || "";
  }

  function applyCredential(text) {
    input.value = text;
    if (colorized) updateRawView();
    if (text.trim()) {
      decode();
      return;
    }
    resetOutput();
  }

  function navigateToEmbeddedCredential(text) {
    const next = (text || "").trim();
    if (!next) return;

    const current = input.value.trim();
    if (current === next) return;
    if (current) {
      history.replaceState({ credential: current }, "", buildCredentialURL(current));
    }
    history.pushState({ credential: next }, "", buildCredentialURL(next));
    applyCredential(next);
  }

  function showColorized() {
    if (colorized) return;
    colorized = true;
    input.classList.add("colorized");
    rawView.style.display = "block";
    updateRawView();
  }

  function hideColorized() {
    if (!colorized) return;
    colorized = false;
    input.classList.remove("colorized");
    rawView.style.display = "none";
  }

  input.addEventListener("scroll", () => {
    if (colorized) {
      rawView.scrollTop = input.scrollTop;
      rawView.scrollLeft = input.scrollLeft;
    }
  });

  let sectionRanges = [];

  function idPart(text) {
    return String(text).replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "empty";
  }

  function reserveId(id) {
    let unique = id;
    for (let n = 2; usedIds.has(unique); n++) unique = id + "-" + n;
    usedIds.add(unique);
    return unique;
  }

  const SECTION_PARTS = ["header", "arrow", "title", "copy", "body"];

  function reserveSection(id) {
    const base = reserveId(id);
    SECTION_PARTS.forEach((part) => usedIds.add(base + "-" + part));
    return base;
  }

  function setId(el, id) {
    el.id = reserveId(id);
    return el.id;
  }

  function updateRawView() {
    const text = input.value.trim();
    sectionRanges = [];
    if (!text) {
      rawView.innerHTML = '<span id="raw-view-empty" style="color:var(--text-dim);font-style:italic">No input</span>';
      return;
    }

    const parts = text.split("~");
    const jwtPart = parts[0];
    const jwtSegments = jwtPart.split(".");

    if (jwtSegments.length >= 2) {
      let html = "";
      let pos = 0;
      let sepCount = 0;
      const separator = (ch) => '<span class="jwt-separator" id="raw-view-sep-' + sepCount++ + '">' + ch + "</span>";

      sectionRanges.push({ start: pos, end: pos + jwtSegments[0].length, section: "header" });
      html += '<span class="jwt-header" id="raw-view-header" data-section="header">' + escapeHtml(jwtSegments[0]) + "</span>";
      pos += jwtSegments[0].length;

      html += separator(".");
      pos += 1;

      sectionRanges.push({ start: pos, end: pos + jwtSegments[1].length, section: "payload" });
      html += '<span class="jwt-payload" id="raw-view-payload" data-section="payload">' + escapeHtml(jwtSegments[1]) + "</span>";
      pos += jwtSegments[1].length;

      if (jwtSegments.length > 2) {
        html += separator(".");
        pos += 1;
        const sigText = jwtSegments.slice(2).join(".");
        sectionRanges.push({ start: pos, end: pos + sigText.length, section: "signature" });
        html += '<span class="jwt-signature" id="raw-view-signature" data-section="signature">' + escapeHtml(sigText) + "</span>";
        pos += sigText.length;
      }

      let kbJwtIndex = -1;
      if (parts.length > 1) {
        for (let i = parts.length - 1; i >= 1; i--) {
          if (parts[i] && parts[i].includes(".")) {
            kbJwtIndex = i;
            break;
          }
        }
      }

      let discIdx = 0;
      for (let i = 1; i < parts.length; i++) {
        html += separator("~");
        pos += 1;
        if (parts[i]) {
          if (i === kbJwtIndex) {
            const kbSegs = parts[i].split(".");
            sectionRanges.push({ start: pos, end: pos + parts[i].length, section: "kb-jwt" });
            html += '<span id="raw-view-kb-jwt" data-section="kb-jwt">';
            html += '<span class="jwt-header" id="raw-view-kb-jwt-header">' + escapeHtml(kbSegs[0]) + "</span>";
            if (kbSegs.length > 1) {
              html += separator(".");
              html += '<span class="jwt-payload" id="raw-view-kb-jwt-payload">' + escapeHtml(kbSegs[1]) + "</span>";
            }
            if (kbSegs.length > 2) {
              html += separator(".");
              html += '<span class="jwt-signature" id="raw-view-kb-jwt-signature">' + escapeHtml(kbSegs.slice(2).join(".")) + "</span>";
            }
            html += "</span>";
            pos += parts[i].length;
          } else {
            const colorIdx = discIdx % DISC_COLORS;
            sectionRanges.push({ start: pos, end: pos + parts[i].length, section: "disc-" + discIdx });
            html += '<span class="jwt-disc-' + colorIdx + '" id="raw-view-disc-' + discIdx + '" data-section="disc-' + discIdx + '">' + escapeHtml(parts[i]) + "</span>";
            pos += parts[i].length;
            discIdx++;
          }
        }
      }

      rawView.innerHTML = html;
    } else {
      rawView.innerHTML = escapeHtml(text);
    }
  }

  let lastHoveredSection = null;

  function clearHoverHighlight() {
    if (!lastHoveredSection) return;
    const sec = lastHoveredSection;
    lastHoveredSection = null;

    const span = rawView.querySelector('[data-section="' + sec + '"]');
    if (span) span.classList.remove("highlight");

    if (sec.startsWith("disc-")) {
      const idx = sec.replace("disc-", "");
      const item = outputEl.querySelector('.disclosure-item[data-disc-index="' + idx + '"]');
      if (item) item.classList.remove("highlight");
    } else {
      const target = outputEl.querySelector('.section[data-section="' + sec + '"]');
      if (target) target.classList.remove("highlight");
    }
  }

  function applyHoverHighlight(sec) {
    if (sec === lastHoveredSection) return;
    clearHoverHighlight();
    lastHoveredSection = sec;

    const span = rawView.querySelector('[data-section="' + sec + '"]');
    if (span) span.classList.add("highlight");

    if (sec.startsWith("disc-")) {
      const idx = sec.replace("disc-", "");
      const item = outputEl.querySelector('.disclosure-item[data-disc-index="' + idx + '"]');
      if (item) {
        item.classList.add("highlight");
        item.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    } else {
      const target = outputEl.querySelector('.section[data-section="' + sec + '"]');
      if (target) {
        target.classList.add("highlight");
        target.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    }
  }

  // elementFromPoint reaches the highlighted layer only while pointer-events allow it.
  function sectionFromPoint(e) {
    input.style.pointerEvents = "none";
    rawView.style.pointerEvents = "auto";
    const el = document.elementFromPoint(e.clientX, e.clientY);
    input.style.pointerEvents = "";
    rawView.style.pointerEvents = "none";
    const span = el && el.closest("[data-section]");
    return span ? span.getAttribute("data-section") : null;
  }

  input.addEventListener("mousemove", (e) => {
    // Highlighting stays fixed while the user selects text.
    if (e.buttons !== 0) return;
    if (!colorized) return;
    const sec = sectionFromPoint(e);
    if (sec) {
      applyHoverHighlight(sec);
    } else {
      clearHoverHighlight();
    }
  });

  input.addEventListener("mouseleave", clearHoverHighlight);

  function showToast(msg) {
    let toast = document.querySelector(".toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.className = "toast";
      toast.id = "toast";
      document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2000);
  }

  function postValidate(body) {
    return fetch(basePath + "api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((res) => res.json());
  }

  // Offline checks show first, so network requests do not delay decoding.
  function decode() {
    const text = input.value.trim();
    if (!text) {
      resetOutput();
      return;
    }

    const seq = ++decodeSeq;

    postValidate({ input: text, offline: true })
      .then((data) => {
        if (seq !== decodeSeq || renderedSeq === seq) return;
        if (data.error) {
          showDecodeError(data.error_description || data.error);
          return;
        }
        render(seq, data, { awaitingNetworkChecks: true });
      })
      .catch((err) => {
        if (seq === decodeSeq && renderedSeq !== seq) showError("Request failed: " + err.message);
      });

    postValidate({ input: text, checkStatus: true })
      .then((data) => {
        if (seq !== decodeSeq) return;
        if (data.error) {
          showDecodeError(data.error_description || data.error);
          return;
        }
        lastData = data;
        lastValidation = data.validation || null;
        if (renderedSeq === seq) {
          replaceValidationBanner(data.validation && data.validation.checks, data.deviations, {});
          return;
        }
        render(seq, data, {});
      })
      .catch(() => {
        if (seq === decodeSeq && renderedSeq === seq) {
          replaceValidationBanner(lastValidation && lastValidation.checks, lastData && lastData.deviations, {});
        }
      });
  }

  function render(seq, data, opts) {
    lastData = data;
    lastValidation = data.validation || null;
    renderedSeq = seq;
    showResult(data, opts);
    showColorized();
  }

  function showDecodeError(message) {
    showError(message);
    formatBadge.className = "badge hidden";
    lastData = null;
    lastValidation = null;
    renderedSeq = -1;
  }

  // Only the banner is replaced, so the reader's expanded and collapsed sections stay.
  function replaceValidationBanner(checks, deviations, opts) {
    if (!checks) return;
    const existing = outputEl.querySelector(".validity-banner");
    if (!existing) return;
    existing.replaceWith(renderValidationBanner(checks, deviations, opts));
  }

  function verifySignature(keyText, trustListURL) {
    const text = input.value.trim();
    if (!text) return;

    const body = { input: text, checkStatus: true };
    if (keyText) body.key = keyText;
    if (trustListURL) body.trustListURL = trustListURL;

    const seq = ++decodeSeq;
    postValidate(body)
      .then((data) => {
        if (seq !== decodeSeq) return;
        if (data.error) {
          showToast("Verification error: " + (data.error_description || data.error));
          return;
        }
        render(seq, data, {});
      })
      .catch((err) => {
        showToast("Verification failed: " + err.message);
      });
  }

  // Debounce typing, but decode pasted credentials as soon as input updates.
  const TYPING_DECODE_DELAY = 300;
  const PASTE_DECODE_DELAY = 10;

  // A paste fires both paste and input. Only the decode that is due first
  // runs, so the credential is decoded once.
  function scheduleDecode(delay) {
    const dueAt = Date.now() + delay;
    if (decodeTimer !== null && decodeDueAt <= dueAt) return;
    clearTimeout(decodeTimer);
    decodeDueAt = dueAt;
    decodeTimer = setTimeout(() => {
      decodeTimer = null;
      decode();
    }, delay);
  }

  input.addEventListener("input", () => {
    if (colorized) updateRawView();
    scheduleDecode(TYPING_DECODE_DELAY);
  });
  input.addEventListener("paste", () => {
    scheduleDecode(PASTE_DECODE_DELAY);
  });

  function showError(msg) {
    outputEl.innerHTML = '<div class="error" id="output-error">' + escapeHtml(msg) + "</div>";
  }

  function showResult(data, opts) {
    updateBadge(data.format);
    outputEl.innerHTML = "";
    usedIds = new Set();

    const summary = extractSummary(data);
    if (summary) {
      outputEl.appendChild(renderSummaryLine(summary));
    }

    if (data.validation && data.validation.checks) {
      outputEl.appendChild(renderValidationBanner(data.validation.checks, data.deviations, opts));
    }

    const fmt = data.format;

    if (fmt === "dc+sd-jwt") {
      renderSDJWT(data);
    } else if (fmt === "jwt" || fmt === "jwt_vc_json") {
      renderJWT(data);
    } else if (fmt === "mso_mdoc") {
      renderMDOC(data);
    } else {
      outputEl.appendChild(renderJSON(data, "output-json"));
    }
  }

  function extractSummary(data) {
    const parts = [];
    if (data.format === "mso_mdoc") {
      if (data.docType) parts.push({ label: "DocType", value: data.docType });
      if (data.claims) {
        for (const ns of Object.keys(data.claims)) {
          const c = data.claims[ns];
          if (c.issuing_authority) parts.push({ label: "Issuer", value: String(c.issuing_authority) });
          if (c.issuing_country) parts.push({ label: "Country", value: String(c.issuing_country) });
        }
      }
    } else if (data.payload) {
      if (data.payload.iss) parts.push({ label: "Issuer", value: data.payload.iss });
      if (data.payload.sub) parts.push({ label: "Subject", value: data.payload.sub });
      if (data.payload.vct) parts.push({ label: "Type", value: data.payload.vct });
    }
    return parts.length ? parts : null;
  }

  function renderSummaryLine(parts) {
    const el = document.createElement("div");
    el.className = "issuer-summary";
    setId(el, "output-summary");
    parts.forEach((p) => {
      const chip = document.createElement("span");
      chip.className = "summary-chip";
      const chipId = setId(chip, "output-summary-" + idPart(p.label).toLowerCase());
      const label = document.createElement("span");
      label.className = "summary-chip-label";
      setId(label, chipId + "-label");
      label.textContent = p.label;
      const value = document.createElement("span");
      value.className = "summary-chip-value";
      setId(value, chipId + "-value");
      value.textContent = p.value;
      value.title = p.value;
      chip.appendChild(label);
      chip.appendChild(value);
      el.appendChild(chip);
    });
    return el;
  }

  function updateBadge(format) {
    if (format === "dc+sd-jwt") {
      formatBadge.textContent = "SD-JWT";
      formatBadge.className = "badge sd-jwt";
    } else if (format === "jwt" || format === "jwt_vc_json") {
      formatBadge.textContent = format === "jwt_vc_json" ? "JWT VC" : "JWT";
      formatBadge.className = "badge jwt";
    } else if (format === "mso_mdoc") {
      formatBadge.textContent = "mdoc";
      formatBadge.className = "badge mdoc";
    } else {
      formatBadge.className = "badge hidden";
    }
  }

  const CHECK_NAMES = {
    type: "Type",
    expiry: "Expiry",
    integrity: "Integrity",
    "trusted list": "Trusted list",
    signature: "Signature",
    trust: "Trust",
    status: "Status",
    "status list signature": "Status list signature",
    haip: "HAIP",
    structure: "Structure",
  };

  function checkName(name) {
    return CHECK_NAMES[name] || name.charAt(0).toUpperCase() + name.slice(1);
  }

  // A passing type check names the typ value, which keeps its case.
  function checkDetail(c) {
    const detail = c.detail || "";
    if (c.name === "type" && c.status === "pass") return detail;
    return detail.charAt(0).toUpperCase() + detail.slice(1);
  }

  function plural(n, one, many) {
    return n + " " + (n === 1 ? one : many);
  }

  // The trust check and the status list signature check usually name the
  // same trusted list. Each list appears once, on the first check naming it.
  function checkItems(checks) {
    const shown = new Set();
    return checks.map((c) => {
      const item = { check: c.name, name: checkName(c.name), detail: checkDetail(c) };
      const anchor = c.status === "pass" ? c.anchor : null;
      if (!anchor) return item;
      if (c.name === "trust") item.detail = "";
      else item.detail = item.detail.replace(/^Valid, s/, "S");
      if (anchor.list_url && !shown.has(anchor.list_url)) {
        shown.add(anchor.list_url);
        item.anchor = anchor;
      }
      return item;
    });
  }

  function anchorHtml(anchor, id, ownLine) {
    const url = String(anchor.list_url);
    const name = url.replace(/\/+$/, "").split("/").pop() || url;
    const list = /^https?:\/\//i.test(url)
      ? '<a href="' + escapeHtml(url) + '" title="' + escapeHtml(url) + '" target="_blank" rel="noopener" id="' + id + '-link">' + escapeHtml(name) + " ↗</a>"
      : escapeHtml(name);
    return '<span class="vg-anchor' + (ownLine ? " vg-anchor-line" : "") + '" id="' + id + '">' + (anchor.entry ? escapeHtml(anchor.entry) + ", trusted list " : "Trusted list ") + list + "</span>";
  }

  function renderValidationBanner(checks, deviations, opts) {
    const banner = document.createElement("div");
    banner.className = "validity-banner";
    banner.id = "output-validation";

    checks = checks || [];
    deviations = deviations || [];
    const awaiting = !!(opts && opts.awaitingNetworkChecks);
    const isPending = (c) => awaiting && c.needsNetwork === true;
    const pending = checks.filter(isPending);

    const passed = [];
    const warnings = [];
    const notChecked = [];
    const failed = [];
    const settled = checks.filter((c) => !isPending(c));
    checkItems(settled).forEach((item, i) => {
      const status = settled[i].status;
      if (status === "pass") passed.push(item);
      else if (status === "fail") failed.push(item);
      else if (status === "warning") warnings.push(item);
      else notChecked.push(item);
    });
    deviations.forEach((d) => failed.push({ check: "structure", name: checkName("structure"), detail: d }));

    const sig = checks.find((c) => c.name === "signature");
    const sigValid = sig && sig.status === "pass";

    let icon, label, cls;
    const notes = [];
    if (pending.length > 0) {
      icon = "\u22ef"; label = "Checking"; cls = "checking";
      notes.push(pending.map((c) => checkName(c.name).toLowerCase()).join(", "));
    } else {
      if (failed.length > 0) {
        icon = "\u2717"; label = "Invalid"; cls = "expired";
        notes.push(plural(failed.length, "check failed", "checks failed"));
      } else if (sigValid) {
        icon = "\u2713"; label = "Valid"; cls = "valid";
      } else {
        icon = "\u26a0"; label = "Unverified"; cls = "unverified";
      }
      if (warnings.length > 0) notes.push(plural(warnings.length, "warning", "warnings"));
      if (notChecked.length > 0) notes.push(notChecked.length + " not checked");
    }
    banner.classList.add(cls);

    let html = '<div class="verification-head" id="output-validation-head">';
    html += '<span class="verification-verdict" id="output-validation-verdict">' + icon + " " + label + "</span>";
    if (notes.length) html += '<span class="validity-detail" id="output-validation-summary">' + escapeHtml(notes.join(", ")) + "</span>";
    html += "</div>";

    html += '<div class="verification-groups" id="output-validation-groups">';
    html += verificationGroup("Failed", "vg-violations", "\u2717", failed, "output-validation-violations");
    html += verificationGroup("Warnings", "vg-warnings", "!", warnings, "output-validation-warnings");
    html += verificationGroup("Not checked", "vg-cant", "\u2014", notChecked, "output-validation-not-checked");
    html += verificationGroup("Passed", "vg-valid", "\u2713", passed, "output-validation-valid");
    html += "</div>";

    const verifyLabel = sigValid ? "Re-verify signature" : "Verify signature";
    html += '<details class="verify-details" id="output-verify"><summary id="output-verify-summary">' + verifyLabel + " with a key or trusted list</summary>";
    html += '<div class="verify-inline" id="output-verify-form">';
    html += '<label class="verify-label" id="output-verify-key-label">Public Key (PEM or JWK)</label>';
    html += '<textarea class="verify-input verify-inline-key" id="output-verify-key" rows="3" placeholder="Paste PEM or JWK…" spellcheck="false"></textarea>';
    html += '<label class="verify-label" id="output-verify-trusted-list-label">Trusted list URL</label>';
    html += '<input class="verify-input verify-inline-tl" id="output-verify-trusted-list" type="text" placeholder="https://...">';
    html += '<button class="btn verify-btn verify-inline-btn" id="output-verify-btn">' + verifyLabel + "</button>";
    html += "</div></details>";

    banner.innerHTML = html;

    const verifyInlineBtn = banner.querySelector(".verify-inline-btn");
    const keyInput = banner.querySelector(".verify-inline-key");
    const tlInput = banner.querySelector(".verify-inline-tl");
    verifyInlineBtn.addEventListener("click", () => {
      const keyText = keyInput.value.trim();
      const tlUrl = tlInput.value.trim();
      if (!keyText && !tlUrl) {
        showToast("Provide a public key or trusted list URL");
        return;
      }
      verifyInlineBtn.disabled = true;
      verifyInlineBtn.textContent = "Verifying…";
      verifySignature(keyText, tlUrl);
    });

    return banner;
  }

  function verificationGroup(title, cls, icon, items, id) {
    if (items.length === 0) return "";
    let h = '<div class="verification-group ' + cls + '" id="' + id + '"><div class="vg-title" id="' + id + '-title">' + title + "</div>";
    items.forEach((it, i) => {
      const itemId = id + "-" + i;
      h += '<div class="vg-item" id="' + itemId + '" data-check="' + escapeHtml(it.check) + '"><span class="vg-icon" id="' + itemId + '-icon">' + icon + "</span>";
      h += '<span class="vg-name" id="' + itemId + '-name">' + escapeHtml(it.name) + "</span>";
      // Every item fills the three grid columns, also without a detail.
      h += '<span class="vg-detail" id="' + itemId + '-detail">' + escapeHtml(it.detail);
      if (it.anchor) h += anchorHtml(it.anchor, itemId + "-anchor", !!it.detail);
      h += "</span>";
      h += "</div>";
    });
    return h + "</div>";
  }

  function relativeTime(date) {
    const now = Date.now();
    let diff = date.getTime() - now;
    const future = diff > 0;
    diff = Math.abs(diff);

    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    const months = Math.floor(days / 30);

    let str;
    if (months >= 2) str = months + " months";
    else if (months === 1) str = "1 month";
    else if (days >= 2) str = days + " days";
    else if (days === 1) str = "1 day";
    else if (hours >= 2) str = hours + " hours";
    else if (hours === 1) str = "1 hour";
    else if (minutes >= 2) str = minutes + " minutes";
    else str = "1 minute";

    return future ? "in " + str : str + " ago";
  }

  function renderSDJWT(data) {
    const header = reserveSection("output-header");
    appendSection("Header", renderJSONBlock(data.header, null, header + "-json"), data.header, "header", header);
    const payload = reserveSection("output-payload");
    appendSection("Payload (signed claims)", renderJSONBlock(data.payload, { timestampKeys: TIMESTAMP_FIELDS }, payload + "-json"), data.payload, "payload", payload);

    if (data.disclosures && data.disclosures.length > 0) {
      const discBase = reserveSection("output-disclosures");
      const disc = document.createElement("div");
      data.disclosures.forEach((d, idx) => {
        const item = document.createElement("div");
        item.className = "disclosure-item";
        const itemId = setId(item, discBase + "-" + idx);
        item.setAttribute("data-disc-index", idx);
        const colorIdx = idx % DISC_COLORS;
        item.style.borderLeftColor = "var(--disc-color-" + colorIdx + ", var(--accent))";
        const name = d.isArrayEntry ? "(array element)" : d.name;
        const valStr = typeof d.value === "object" ? JSON.stringify(d.value) : String(d.value);
        const truncatedDigest = d.digest ? d.digest.substring(0, 16) + "\u2026" : "";
        const nameEl = document.createElement("span");
        nameEl.className = "disclosure-name";
        setId(nameEl, itemId + "-name");
        nameEl.textContent = name;
        item.appendChild(nameEl);
        item.appendChild(document.createTextNode(": "));
        item.appendChild(renderInlineValue(valStr, "disclosure-value", name, itemId + "-value"));

        const meta = document.createElement("div");
        meta.className = "disclosure-meta";
        setId(meta, itemId + "-meta");
        meta.appendChild(document.createTextNode("salt: " + d.salt + " | digest: "));
        const digest = document.createElement("span");
        digest.className = "digest-truncated";
        setId(digest, itemId + "-digest");
        digest.title = d.digest;
        digest.textContent = truncatedDigest;
        meta.appendChild(digest);
        // A disclosure reveals a claim only when the signed credential references its
        // digest.
        if (d.referenced === true) {
          meta.appendChild(document.createTextNode(" \u00b7 matches _sd"));
        } else if (d.referenced === false) {
          const bad = document.createElement("span");
          bad.className = "disclosure-unreferenced";
          setId(bad, itemId + "-unreferenced");
          bad.textContent = " \u00b7 NOT REFERENCED BY THE CREDENTIAL";
          meta.appendChild(bad);
        }
        item.appendChild(meta);
        disc.appendChild(item);
      });
      disc.insertBefore(
        renderNote(
          "Each disclosure matches a digest signed by the issuer.",
          discBase + "-note"),
        disc.firstChild);
      appendSection("Disclosures (" + data.disclosures.length + ")", disc, data.disclosures, "disclosures", discBase);

      disc.querySelectorAll(".disclosure-item[data-disc-index]").forEach((item) => {
        const idx = item.getAttribute("data-disc-index");
        item.addEventListener("mouseenter", () => {
          item.classList.add("highlight");
          const span = rawView.querySelector('[data-section="disc-' + idx + '"]');
          if (span) {
            span.classList.add("highlight");
            span.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        });
        item.addEventListener("mouseleave", () => {
          item.classList.remove("highlight");
          const span = rawView.querySelector('[data-section="disc-' + idx + '"]');
          if (span) span.classList.remove("highlight");
        });
      });
    }

    if (data.resolvedClaims) {
      const disclosedNames = new Set();
      if (data.disclosures) {
        data.disclosures.forEach((d) => {
          if (d.name) disclosedNames.add(d.name);
        });
      }
      const resolved = reserveSection("output-resolved-claims");
      appendSection("Resolved claims", renderResolvedClaims(data.resolvedClaims, disclosedNames, resolved), data.resolvedClaims, undefined, resolved);
    }

    if (data.keyBindingJWT) {
      const kbBase = reserveSection("output-kb-jwt");
      const kb = document.createElement("div");
      kb.appendChild(createSubSection("Header", renderJSONBlock(data.keyBindingJWT.header, null, kbBase + "-header-block-json"), kbBase + "-header-block"));
      kb.appendChild(createSubSection("Payload", renderJSONBlock(data.keyBindingJWT.payload, { timestampKeys: TIMESTAMP_FIELDS }, kbBase + "-payload-block-json"), kbBase + "-payload-block"));
      appendSection("Key Binding JWT", kb, data.keyBindingJWT, "kb-jwt", kbBase);
    }

    if (data.warnings && data.warnings.length > 0) {
      const notes = reserveSection("output-notes");
      const w = document.createElement("div");
      data.warnings.forEach((msg, i) => {
        const p = document.createElement("div");
        setId(p, notes + "-" + i);
        p.style.color = "var(--yellow)";
        p.textContent = "\u26A0 " + msg;
        w.appendChild(p);
      });
      appendSection("Notes", w, undefined, undefined, notes);
    }
  }

  function renderResolvedClaims(claims, disclosedNames, base) {
    const el = document.createElement("div");
    el.className = "resolved-claims-list";

    const disclosed = [];
    const standard = [];
    const keys = Object.keys(claims).sort();
    keys.forEach((k) => {
      const val = claims[k];
      const valStr = typeof val === "object" && val !== null ? JSON.stringify(val) : String(val);
      if (disclosedNames.has(k)) {
        disclosed.push({ key: k, value: valStr });
      } else {
        standard.push({ key: k, value: valStr });
      }
    });

    if (disclosed.length > 0) {
      const label = document.createElement("div");
      label.className = "resolved-group-label disclosed";
      setId(label, base + "-disclosed-label");
      label.textContent = "Disclosed (" + disclosed.length + ")";
      el.appendChild(label);
      disclosed.forEach((c) => {
        el.appendChild(renderClaimCard(c.key, c.value, "disclosed", base + "-" + idPart(c.key)));
      });
    }

    if (standard.length > 0) {
      const label = document.createElement("div");
      label.className = "resolved-group-label";
      setId(label, base + "-standard-label");
      label.textContent = "Standard (" + standard.length + ")";
      el.appendChild(label);
      standard.forEach((c) => {
        el.appendChild(renderClaimCard(c.key, c.value, "standard", base + "-" + idPart(c.key)));
      });
    }

    return el;
  }

  function renderClaimCard(key, value, type, id) {
    const item = document.createElement("div");
    item.className = "claim-item" + (type === "disclosed" ? " claim-disclosed" : "");
    const itemId = setId(item, id);
    const name = document.createElement("span");
    name.className = "claim-name";
    setId(name, itemId + "-name");
    name.textContent = key;
    item.appendChild(name);
    item.appendChild(document.createTextNode(": "));
    item.appendChild(renderInlineValue(value, "claim-value", key, itemId + "-value"));
    return item;
  }

  function renderJWT(data) {
    const header = reserveSection("output-header");
    appendSection("Header", renderJSONBlock(data.header, null, header + "-json"), data.header, "header", header);
    const payload = reserveSection("output-payload");
    appendSection("Payload", renderJSONBlock(data.payload, { timestampKeys: TIMESTAMP_FIELDS }, payload + "-json"), data.payload, "payload", payload);
  }

  const MDOC_NOTES = {
    structure:
      "issuerSigned is signed by the issuer. deviceSigned is signed by the holder when presenting.",
    issuerAuth:
      "COSE_Sign1 over the Mobile Security Object.",
    mso:
      "Digests of the elements, signed by the issuer.",
    items:
      "Each element matches a digest in the Mobile Security Object.",
    deviceKey:
      "Holder key (cnf in an SD-JWT).",
    deviceAuth:
      "Holder signature over the session transcript. A bare credential has none.",
  };

  function renderNote(text, id) {
    const el = document.createElement("div");
    el.className = "format-note";
    setId(el, id);
    el.textContent = text;
    return el;
  }

  function renderMDOC(data) {
    const infoBase = reserveSection("output-document-info");
    const info = document.createElement("div");
    info.appendChild(renderNote(MDOC_NOTES.structure, infoBase + "-note"));
    info.appendChild(renderKV("DocType", data.docType, infoBase + "-doctype"));
    if (data.isDeviceResponse) {
      info.appendChild(renderKV("Container", "DeviceResponse", infoBase + "-container"));
      if (data.responseVersion) info.appendChild(renderKV("version", data.responseVersion, infoBase + "-version"));
      if (data.responseStatus !== undefined) info.appendChild(renderKV("status", data.responseStatus, infoBase + "-status"));
    } else {
      info.appendChild(renderKV("Container", "IssuerSigned", infoBase + "-container"));
    }
    appendSection("Document info", info, { docType: data.docType }, undefined, infoBase);

    if (data.issuerSignedItems) {
      Object.keys(data.issuerSignedItems).sort().forEach((ns) => {
        const items = data.issuerSignedItems[ns];
        const nsBase = reserveSection("output-namespace-" + idPart(ns));
        const el = document.createElement("div");
        el.appendChild(renderNote(MDOC_NOTES.items, nsBase + "-note"));
        items.forEach((item) => {
          el.appendChild(renderIssuerSignedItem(item, nsBase + "-" + idPart(item.elementIdentifier)));
        });
        appendSection("issuerSigned.nameSpaces \u2192 " + ns + " (" + items.length + " elements)", el, items, undefined, nsBase);
      });
    }

    if (data.issuerAuth) {
      const base = reserveSection("output-issuer-auth");
      const el = document.createElement("div");
      el.appendChild(renderNote(MDOC_NOTES.issuerAuth, base + "-note"));
      el.appendChild(renderKV("Structure", data.issuerAuth.structure, base + "-structure"));
      if (data.issuerAuth.protected) {
        el.appendChild(createSubSection("protected header (signed)", renderJSONBlock(data.issuerAuth.protected, null, base + "-protected-json"), base + "-protected"));
      }
      if (data.issuerAuth.unprotected) {
        el.appendChild(createSubSection("unprotected header (not signed)", renderJSONBlock(data.issuerAuth.unprotected, null, base + "-unprotected-json"), base + "-unprotected"));
      }
      const payload = document.createElement("div");
      payload.appendChild(renderKV("payload", data.issuerAuth.payload + " (" + data.issuerAuth.payloadBytes + " bytes)", base + "-payload"));
      payload.appendChild(renderKV("signature", data.issuerAuth.signatureBytes + " bytes", base + "-signature"));
      el.appendChild(payload);
      appendSection("issuerSigned.issuerAuth (COSE_Sign1)", el, data.issuerAuth, undefined, base);
    }

    if (data.mso) {
      const mso = data.mso;
      const base = reserveSection("output-mso");
      const el = document.createElement("div");
      el.appendChild(renderNote(MDOC_NOTES.mso, base + "-note"));
      // Keep the MSO field order from ISO 18013-5.
      if (mso.version) el.appendChild(renderKV("version", mso.version, base + "-version"));
      if (mso.digestAlgorithm) el.appendChild(renderKV("digestAlgorithm", mso.digestAlgorithm, base + "-digest-algorithm"));
      if (mso.valueDigests) {
        el.appendChild(createSubSection("valueDigests (one per element)", renderJSONBlock(mso.valueDigests, null, base + "-value-digests-json"), base + "-value-digests"));
      }
      el.appendChild(renderKV("deviceKeyInfo", "shown as its own section below", base + "-device-key-info"));
      if (mso.docType) el.appendChild(renderKV("docType", mso.docType, base + "-doctype"));
      if (mso.validityInfo) {
        const vi = mso.validityInfo;
        const validity = document.createElement("div");
        if (vi.signed) validity.appendChild(renderKV("signed", vi.signed, base + "-validity-signed"));
        if (vi.validFrom) validity.appendChild(renderKV("validFrom", vi.validFrom, base + "-validity-valid-from"));
        if (vi.validUntil) validity.appendChild(renderKV("validUntil", vi.validUntil, base + "-validity-valid-until"));
        el.appendChild(createSubSection("validityInfo", validity, base + "-validity"));
      }
      if (mso.status) {
        el.appendChild(createSubSection("status", renderJSONBlock(mso.status, null, base + "-status-json"), base + "-status"));
      }
      appendSection("issuerAuth.payload \u2192 Mobile Security Object", el, mso, undefined, base);
    }

    if (data.deviceKey) {
      const base = reserveSection("output-device-key");
      const el = document.createElement("div");
      el.appendChild(renderNote(MDOC_NOTES.deviceKey, base + "-note"));
      if (!data.deviceKey.bound) {
        el.appendChild(renderKV("Bound to a holder key", "no", base + "-bound"));
      } else if (data.deviceKey.error) {
        el.appendChild(renderKV("Bound to a holder key", "yes", base + "-bound"));
        el.appendChild(renderKV("Key", "unreadable: " + data.deviceKey.error, base + "-key"));
      } else {
        el.appendChild(renderKV("Type", data.deviceKey.type + " " + data.deviceKey.curve, base + "-type"));
        el.appendChild(renderKV("Thumbprint", data.deviceKey.thumbprint, base + "-thumbprint"));
      }
      if (data.deviceKey.coseKey) {
        el.appendChild(createSubSection("COSE_Key", renderJSONBlock(data.deviceKey.coseKey, null, base + "-cose-key-json"), base + "-cose-key"));
      }
      appendSection("mso.deviceKeyInfo \u2192 device key", el, data.deviceKey, undefined, base);
    }

    const authBase = reserveSection("output-device-auth");
    const deviceAuth = document.createElement("div");
    deviceAuth.appendChild(renderNote(MDOC_NOTES.deviceAuth, authBase + "-note"));
    if (data.deviceAuth) {
      if (data.deviceAuthType) deviceAuth.appendChild(renderKV("Type", data.deviceAuthType, authBase + "-type"));
      deviceAuth.appendChild(createSubSection("COSE", renderJSONBlock(data.deviceAuth, null, authBase + "-cose-json"), authBase + "-cose"));
    } else {
      deviceAuth.appendChild(renderKV("Present", "No (a credential, not a presentation)", authBase + "-present"));
    }
    appendSection("deviceSigned.deviceAuth", deviceAuth, data.deviceAuth || {}, undefined, authBase);
  }

  function renderIssuerSignedItem(item, id) {
    const wrap = document.createElement("div");
    wrap.className = "mdoc-item";
    const itemId = setId(wrap, id);

    const head = document.createElement("div");
    head.className = "claim-item";
    setId(head, itemId + "-claim");
    const name = document.createElement("span");
    name.className = "claim-name";
    setId(name, itemId + "-name");
    name.textContent = item.elementIdentifier;
    head.appendChild(name);
    head.appendChild(document.createTextNode(": "));
    const val = item.elementValue;
    const valStr = typeof val === "object" && val !== null ? JSON.stringify(val, null, 2) : String(val);
    head.appendChild(renderInlineValue(valStr, "claim-value", item.elementIdentifier, itemId + "-value"));
    wrap.appendChild(head);

    const meta = document.createElement("div");
    meta.className = "mdoc-item-meta";
    setId(meta, itemId + "-meta");
    const parts = [
      "digestID " + item.digestID,
      "salt " + item.randomBytes + " bytes",
    ];
    if (item.digestMatches === true) {
      parts.push("digest matches the MSO");
    } else if (item.digestMatches === false) {
      parts.push("DIGEST DOES NOT MATCH");
      meta.classList.add("mdoc-item-bad");
    } else if (item.digestError) {
      parts.push(item.digestError);
    }
    meta.textContent = parts.join(" \u00b7 ");
    meta.title = item.random ? "salt: " + item.random + "\ndigest: " + (item.digest || "?") : "";
    wrap.appendChild(meta);
    return wrap;
  }

  function appendSection(title, contentEl, copyData, sectionId, id) {
    const section = document.createElement("div");
    section.className = "section";
    section.id = id;
    if (sectionId) section.setAttribute("data-section", sectionId);

    const header = document.createElement("div");
    header.className = "section-header";
    header.id = id + "-header";

    const arrow = document.createElement("span");
    arrow.className = "arrow";
    arrow.id = id + "-arrow";
    arrow.textContent = "\u25BC";

    const titleSpan = document.createElement("span");
    titleSpan.id = id + "-title";
    titleSpan.textContent = title;

    header.appendChild(arrow);
    header.appendChild(titleSpan);

    if (copyData !== undefined) {
      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-btn";
      copyBtn.id = id + "-copy";
      copyBtn.textContent = "Copy";
      copyBtn.title = "Copy section as JSON";
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const text = JSON.stringify(copyData, null, 2);
        navigator.clipboard.writeText(text).then(() => {
          copyBtn.textContent = "Copied!";
          copyBtn.classList.add("copied");
          setTimeout(() => {
            copyBtn.textContent = "Copy";
            copyBtn.classList.remove("copied");
          }, 1500);
        }).catch(() => {
          showToast("Failed to copy");
        });
      });
      header.appendChild(copyBtn);
    }

    const body = document.createElement("div");
    body.className = "section-body";
    body.id = id + "-body";
    body.appendChild(contentEl);

    header.addEventListener("click", (e) => {
      if (e.target.closest(".copy-btn")) return;
      const collapsed = body.classList.toggle("collapsed");
      arrow.classList.toggle("collapsed", collapsed);
    });

    if (sectionId) {
      section.addEventListener("mouseenter", () => {
        section.classList.add("highlight");
        if (sectionId === "disclosures") {
          const spans = rawView.querySelectorAll('[data-section^="disc-"]');
          spans.forEach((s) => s.classList.add("highlight"));
          if (spans.length) spans[0].scrollIntoView({ behavior: "smooth", block: "nearest" });
        } else {
          const span = rawView.querySelector('[data-section="' + sectionId + '"]');
          if (span) {
            span.classList.add("highlight");
            span.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        }
      });
      section.addEventListener("mouseleave", () => {
        section.classList.remove("highlight");
        if (sectionId === "disclosures") {
          rawView.querySelectorAll('[data-section^="disc-"]').forEach((s) => s.classList.remove("highlight"));
        } else {
          const span = rawView.querySelector('[data-section="' + sectionId + '"]');
          if (span) span.classList.remove("highlight");
        }
      });
    }

    section.appendChild(header);
    section.appendChild(body);
    outputEl.appendChild(section);
  }

  function createSubSection(title, contentEl, id) {
    const wrap = document.createElement("div");
    const wrapId = setId(wrap, id);
    wrap.style.margin = "6px 0";
    const label = document.createElement("div");
    setId(label, wrapId + "-label");
    label.style.color = "var(--cyan)";
    label.style.fontWeight = "600";
    label.style.marginBottom = "4px";
    label.textContent = title;
    wrap.appendChild(label);
    wrap.appendChild(contentEl);
    return wrap;
  }

  function renderKV(key, value, id) {
    const line = document.createElement("div");
    line.className = "json-line";
    const lineId = setId(line, id);
    const keyEl = document.createElement("span");
    keyEl.className = "json-key";
    setId(keyEl, lineId + "-key");
    keyEl.textContent = key;
    line.appendChild(keyEl);
    line.appendChild(document.createTextNode(": "));
    line.appendChild(renderInlineValue(String(value), "json-string", undefined, lineId + "-value"));
    return line;
  }

  function renderJSONBlock(obj, opts, id) {
    const el = document.createElement("pre");
    el.className = "json-block";
    const blockId = setId(el, id);
    appendJSONValue(el, obj, 0, opts || {}, null, blockId);
    return el;
  }

  function appendJSONValue(parent, value, depth, opts, currentKey, path) {
    if (Array.isArray(value)) {
      parent.appendChild(document.createTextNode("["));
      if (value.length > 0) {
        parent.appendChild(document.createTextNode("\n"));
        value.forEach((entry, index) => {
          parent.appendChild(document.createTextNode("  ".repeat(depth + 1)));
          appendJSONValue(parent, entry, depth + 1, opts, currentKey, path + "-" + index);
          if (index < value.length - 1) {
            parent.appendChild(document.createTextNode(","));
          }
          parent.appendChild(document.createTextNode("\n"));
        });
        parent.appendChild(document.createTextNode("  ".repeat(depth)));
      }
      parent.appendChild(document.createTextNode("]"));
      return;
    }

    if (value && typeof value === "object") {
      const entries = Object.entries(value);
      parent.appendChild(document.createTextNode("{"));
      if (entries.length > 0) {
        parent.appendChild(document.createTextNode("\n"));
        entries.forEach(([key, entry], index) => {
          parent.appendChild(document.createTextNode("  ".repeat(depth + 1)));
          const entryPath = path + "-" + idPart(key);
          appendJSONToken(parent, "json-key", JSON.stringify(key), "", entryPath + "-key");
          parent.appendChild(document.createTextNode(": "));
          appendJSONValue(parent, entry, depth + 1, opts, key, entryPath);
          if (index < entries.length - 1) {
            parent.appendChild(document.createTextNode(","));
          }
          parent.appendChild(document.createTextNode("\n"));
        });
        parent.appendChild(document.createTextNode("  ".repeat(depth)));
      }
      parent.appendChild(document.createTextNode("}"));
      return;
    }

    if (typeof value === "string") {
      parent.appendChild(createEmbeddedValueElement(value, { quoted: true, id: path + "-value" }));
      return;
    }

    if (typeof value === "number") {
      const title = timestampTitle(value, currentKey, opts);
      appendJSONToken(parent, title ? "json-number timestamp-hover" : "json-number", String(value), title, path + "-value");
      return;
    }

    if (typeof value === "boolean") {
      appendJSONToken(parent, "json-bool", String(value), "", path + "-value");
      return;
    }

    if (value === null) {
      appendJSONToken(parent, "json-null", "null", "", path + "-value");
      return;
    }

    appendJSONToken(parent, "json-null", JSON.stringify(value), "", path + "-value");
  }

  function appendJSONToken(parent, className, text, title, id) {
    const span = document.createElement("span");
    span.className = className;
    setId(span, id);
    span.textContent = text;
    if (title) span.title = title;
    parent.appendChild(span);
  }

  function timestampTitle(value, currentKey, opts) {
    const tsKeys = opts && opts.timestampKeys;
    if (!tsKeys || !currentKey || !tsKeys.has(currentKey)) {
      return "";
    }
    if (!Number.isFinite(value) || value <= 1000000000 || value >= 4102444800) {
      return "";
    }

    const date = new Date(value * 1000);
    const iso = date.toISOString().replace(/\.\d+Z$/, "Z");
    return iso + " (" + relativeTime(date) + ")";
  }

  function renderInlineValue(value, className, key, id) {
    const wrap = document.createElement("span");
    wrap.className = className;
    const wrapId = setId(wrap, id);
    const title = timestampTitle(Number(value), key, { timestampKeys: TIMESTAMP_FIELDS });
    if (title) {
      wrap.className = className + " timestamp-hover";
      wrap.title = title;
    }
    if (typeof value === "string") {
      wrap.appendChild(createEmbeddedValueElement(value, { quoted: false, plainStringClass: className, id: wrapId + "-token" }));
    } else {
      wrap.textContent = String(value);
    }
    return wrap;
  }

  // Long values such as portraits are truncated until expanded, so the rest of the
  // output stays visible.
  const MAX_INLINE_VALUE_CHARS = 300;

  function createEmbeddedValueElement(value, opts) {
    const quoted = !!(opts && opts.quoted);
    const token = quoted ? JSON.stringify(value) : value;
    const el = createValueToken(value, token, quoted, opts);
    if (token.length <= MAX_INLINE_VALUE_CHARS) {
      setId(el, opts.id);
      return el;
    }
    return wrapLongValue(el, token, value, opts.id);
  }

  function createValueToken(value, token, quoted, opts) {
    const info = detectEmbeddedCredential(value);
    if (!info) {
      const span = document.createElement("span");
      span.className = quoted ? "json-string" : (opts && opts.plainStringClass) || "";
      span.textContent = token;
      return span;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.className = "embedded-token" + (quoted ? " json-string" : "");
    button.setAttribute("data-embedded-format", info.format);
    button.title = "Open embedded " + info.label;
    button.textContent = token;
    button.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      navigateToEmbeddedCredential(value);
    });
    return button;
  }

  function wrapLongValue(el, token, value, id) {
    const wrap = document.createElement("span");
    wrap.className = "long-value";
    const wrapId = setId(wrap, id);
    setId(el, wrapId + "-text");

    const head = token.slice(0, MAX_INLINE_VALUE_CHARS) + "…";
    el.classList.add("long-value-token");
    el.textContent = head;
    wrap.appendChild(el);

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "long-value-toggle";
    setId(toggle, wrapId + "-toggle");
    const showAll = "Show all " + token.length + " characters";
    toggle.textContent = showAll;
    let expanded = false;
    toggle.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      expanded = !expanded;
      el.textContent = expanded ? token : head;
      toggle.textContent = expanded ? "Show less" : showAll;
    });
    wrap.appendChild(toggle);

    const image = imageDataURL(value);
    if (image) {
      const img = document.createElement("img");
      img.className = "value-image";
      setId(img, wrapId + "-image");
      img.src = image;
      img.alt = "";
      img.loading = "lazy";
      wrap.appendChild(img);
    }

    return wrap;
  }

  // Accept only Base64 image data URLs.
  const IMAGE_DATA_URL_RE = /^data:image\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+$/i;

  function imageDataURL(value) {
    if (typeof value !== "string") return null;
    const text = value.trim();
    return IMAGE_DATA_URL_RE.test(text) ? text : null;
  }

  function detectEmbeddedCredential(value) {
    if (typeof value !== "string") return null;
    const text = value.trim();
    if (!text) return null;

    if (looksLikeSDJWT(text)) {
      return { format: "sd-jwt", label: "SD-JWT" };
    }
    if (looksLikeJWT(text)) {
      return { format: "jwt", label: "JWT" };
    }
    if (looksLikeMDOC(text)) {
      return { format: "mdoc", label: "mdoc" };
    }

    return null;
  }

  function looksLikeSDJWT(text) {
    if (!text.includes("~")) return false;
    return looksLikeJWT(text.split("~")[0]);
  }

  function looksLikeJWT(text) {
    const parts = text.split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1]) {
      return false;
    }

    const payload = decodeBase64URL(parts[1]);
    if (!payload) {
      return false;
    }

    try {
      const parsed = JSON.parse(new TextDecoder().decode(payload));
      return !!parsed && typeof parsed === "object";
    } catch (_) {
      return false;
    }
  }

  // Short digests can carry a similar CBOR marker, so an embedded mdoc needs a minimum length.
  const MDOC_MIN_BYTES = 64;

  function looksLikeMDOC(text) {
    if (isHexString(text)) {
      const bytes = hexToBytes(text);
      return bytes.length >= MDOC_MIN_BYTES && isCBORStart(bytes[0]);
    }

    const decoded = decodeBase64URL(text);
    return !!decoded && decoded.length >= MDOC_MIN_BYTES && isCBORStart(decoded[0]);
  }

  function isHexString(text) {
    return text.length >= 2 && text.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(text);
  }

  function hexToBytes(text) {
    const bytes = new Uint8Array(text.length / 2);
    for (let i = 0; i < text.length; i += 2) {
      bytes[i / 2] = parseInt(text.slice(i, i + 2), 16);
    }
    return bytes;
  }

  function decodeBase64URL(text) {
    if (!text) return null;
    try {
      const normalized = text.replace(/-/g, "+").replace(/_/g, "/");
      const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
      const binary = atob(normalized + padding);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch (_) {
      return null;
    }
  }

  function isCBORStart(b) {
    const major = b >> 5;
    return major === 4 || major === 5 || major === 6;
  }

  function renderJSON(obj, id) {
    return renderJSONBlock(obj, null, id);
  }

  // Escape quotes too because values appear in HTML attributes.
  function escapeHtml(str) {
    return String(str === undefined || str === null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function prefill(credential) {
    applyCredential(credential);
  }

  const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0;
  const mod = isMac ? "\u2318" : "Ctrl";
  const hintEl = document.querySelector(".shortcut-hint .kbd-hints");
  if (hintEl) {
    hintEl.innerHTML =
      "<kbd>" + mod + "+L</kbd> Focus input &nbsp;&middot;&nbsp; " +
      "<kbd>" + mod + "+Shift+C</kbd> Copy share link &nbsp;&middot;&nbsp; " +
      "Hover timestamps for human-readable dates";
  }

  const queryParams = new URLSearchParams(window.location.search);
  const queryCredential = linkedCredential();
  const queryID = queryParams.get("id");

  window.addEventListener("popstate", (event) => {
    const credential = event.state && typeof event.state.credential === "string"
      ? event.state.credential
      : linkedCredential();
    applyCredential(credential);
  });

  // A mounted decoder can use a wallet credential ID. Other links carry the credential
  // itself.
  function loadWalletCredential(id) {
    return fetch(basePath + "api/credentials/" + encodeURIComponent(id))
      .then((res) => res.json().then((data) => ({ ok: res.ok, data })))
      .then(({ ok, data }) => {
        if (!ok || !data.credential) {
          throw new Error(data.error_description || data.error || "the wallet returned no credential");
        }
        walletCredential = { id: id, credential: data.credential };
        history.replaceState({ credential: data.credential }, "", buildCredentialURL(data.credential));
        prefill(data.credential);
      })
      .catch((e) => {
        outputEl.innerHTML = '<div class="placeholder" id="output-placeholder">Could not load credential ' +
          escapeHtml(id) + ": " + escapeHtml(e.message) + "</div>";
      });
  }

  if (queryID) {
    loadWalletCredential(queryID);
  } else if (queryCredential) {
    history.replaceState({ credential: queryCredential }, "", buildCredentialURL(queryCredential));
    prefill(queryCredential);
  } else {
    fetch(basePath + "api/prefill")
      .then((res) => res.json())
      .then((data) => {
        if (data.credential) {
          history.replaceState({ credential: data.credential }, "", window.location.pathname);
          prefill(data.credential);
        }
      })
      .catch(() => {});
  }

  const menuToggle = document.getElementById("header-menu-toggle");
  const headerMenu = document.getElementById("header-menu");
  function setMenuOpen(open) {
    headerMenu.classList.toggle("open", open);
    menuToggle.setAttribute("aria-expanded", String(open));
  }
  menuToggle.addEventListener("click", () => setMenuOpen(!headerMenu.classList.contains("open")));
  headerMenu.addEventListener("click", (event) => {
    if (event.target.closest("a, button")) setMenuOpen(false);
  });

  const cliOverlay = document.getElementById("cli-overlay");
  document.getElementById("get-cli-link").addEventListener("click", (event) => {
    event.preventDefault();
    cliOverlay.classList.add("active");
  });
  document.getElementById("cli-close").addEventListener("click", () => {
    cliOverlay.classList.remove("active");
  });

  fetch(basePath + "api/meta")
    .then((res) => res.json())
    .then((meta) => {
      document.getElementById("imprint-link").href = basePath + "imprint";
      window.eudiFooter(meta);
      if (meta.wallet) {
        const walletLink = document.getElementById("wallet-link");
        walletLink.textContent = "Wallet";
        walletLink.hidden = false;
      }
      if (meta.demo) {
        document.getElementById("demo-note").hidden = false;
      }
    })
    .catch(() => {});
})();
