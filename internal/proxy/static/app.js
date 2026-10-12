(function () {
  "use strict";

  const entriesEl = document.getElementById("entries");
  const emptyEl = document.getElementById("empty");
  const statusEl = document.getElementById("status");
  const clearBtn = document.getElementById("clear-btn");
  const showAllCheckbox = document.getElementById("show-all");
  const harExportBtn = document.getElementById("har-export");
  const timelineToggle = document.getElementById("timeline-toggle");

  let entries = [];
  let entriesLimit = Infinity;
  // Remember cleared traffic locally so a server resync does not restore it.
  let clearedThroughID = 0;
  let showAll = false;
  let timelineView = localStorage.getItem("proxy-timeline") === "true";
  // A full render keeps what the user opened and closed.
  const expandedEntries = new Set();
  const collapsedFlows = new Set();

  showAllCheckbox.checked = localStorage.getItem("proxy-show-all") === "true";
  showAll = showAllCheckbox.checked;

  showAllCheckbox.addEventListener("change", function () {
    showAll = showAllCheckbox.checked;
    localStorage.setItem("proxy-show-all", showAll);
    renderEntries();
  });

  clearBtn.addEventListener("click", function () {
    for (var i = 0; i < entries.length; i++) {
      if (entries[i].id > clearedThroughID) clearedThroughID = entries[i].id;
    }
    entries = [];
    renderEntries();
  });

  harExportBtn.addEventListener("click", function () {
    fetch("api/har")
      .then(function (r) { return r.blob(); })
      .then(function (blob) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "eudi-dev.har";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      })
      .catch(function (err) {
        console.error("Failed to export HAR:", err);
      });
  });

  updateTimelineButton();
  timelineToggle.addEventListener("click", function () {
    timelineView = !timelineView;
    localStorage.setItem("proxy-timeline", timelineView);
    updateTimelineButton();
    renderEntries();
  });

  function updateTimelineButton() {
    timelineToggle.textContent = timelineView ? "List" : "Timeline";
  }

  function isVisible(entry) {
    return showAll || entry.classLabel !== "Unknown";
  }

  function badgeClass(classLabel) {
    if (classLabel.startsWith("VP")) return "badge-vp";
    if (classLabel.startsWith("VCI")) return "badge-vci";
    if (classLabel.startsWith("OIDC")) return "badge-oidc";
    return "badge-unknown";
  }

  function statusClass(code) {
    if (code < 300) return "ok";
    if (code < 400) return "redirect";
    if (code < 500) return "client-error";
    return "server-error";
  }

  function formatTime(ts) {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-GB", { hour12: false });
  }

  // Escape quotes too because proxied URLs appear in HTML attributes.
  function escapeHtml(s) {
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function idPart(text) {
    return String(text).replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "empty";
  }

  // POSIX single quotes keep every character literal. A quote inside ends
  // the quoting, adds an escaped quote and quotes again.
  function shellQuote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
  }

  function generateCurl(entry) {
    var parts = ["curl -X " + shellQuote(entry.method) + " " + shellQuote(entry.url)];
    if (entry.requestHeaders) {
      for (var key in entry.requestHeaders) {
        if (key.toLowerCase().startsWith("x-proxy-")) continue;
        var vals = entry.requestHeaders[key];
        for (var i = 0; i < vals.length; i++) {
          parts.push("-H " + shellQuote(key + ": " + vals[i]));
        }
      }
    }
    if (entry.requestBody) {
      parts.push("--data-raw " + shellQuote(entry.requestBody));
    }
    return parts.join(" \\\n  ");
  }

  function renderDecoded(decoded, id) {
    if (!decoded) return "";
    let html = '<div class="decoded-fields" id="' + id + '-fields">';
    const seen = {};
    for (const [key, val] of Object.entries(decoded)) {
      let fieldId = id + "-" + idPart(key);
      if (seen[fieldId]) fieldId += "-" + (++seen[fieldId]);
      else seen[fieldId] = 1;
      html += '<span class="decoded-key" id="' + fieldId + '-key">' + escapeHtml(key) + '</span>';
      if (typeof val === "object" && val !== null) {
        html += '<span class="decoded-value" id="' + fieldId + '-value"><pre id="' + fieldId + '-json">' + escapeHtml(JSON.stringify(val, null, 2)) + '</pre></span>';
      } else {
        html += '<span class="decoded-value" id="' + fieldId + '-value">' + escapeHtml(String(val)) + '</span>';
      }
    }
    html += "</div>";
    return html;
  }

  function renderHeaders(headers) {
    if (!headers) return "";
    let lines = [];
    for (const [key, vals] of Object.entries(headers)) {
      for (const v of vals) {
        lines.push(escapeHtml(key + ": " + v));
      }
    }
    return lines.join("\n");
  }

  function renderCredentialLinks(credentials, credentialLabels, id) {
    if (!credentials || credentials.length === 0) return "";
    var html = '<div class="detail-section" id="' + id + '"><h3 id="' + id + '-title">Credentials</h3><div class="credential-links" id="' + id + '-links">';
    for (var i = 0; i < credentials.length; i++) {
      var label;
      if (credentialLabels && credentialLabels[i]) {
        label = "Open " + credentialLabels[i] + " in decoder";
      } else if (credentials.length === 1) {
        label = "Open in decoder";
      } else {
        label = "Open credential " + (i + 1) + " in decoder";
      }
      var href = "decode/#credential=" + encodeURIComponent(credentials[i]);
      html += '<a class="btn credential-link" id="' + id + '-' + i + '" href="' + escapeHtml(href) + '" target="_blank">' + escapeHtml(label) + '</a>';
    }
    html += '</div></div>';
    return html;
  }

  function detailSection(id, title, contentHtml) {
    return '<div class="detail-section" id="' + id + '"><h3 id="' + id + '-title">' + title + '</h3><pre id="' + id + '-content">' + contentHtml + '</pre></div>';
  }

  function renderEntry(entry) {
    const el = document.createElement("div");
    el.className = "entry";
    el.dataset.id = entry.id;
    const id = "entry-" + idPart(entry.id);
    el.id = id;

    const urlPath = entry.url.length > 100 ? entry.url.substring(0, 100) + "..." : entry.url;

    el.innerHTML =
      '<div class="entry-header" id="' + id + '-header">' +
        '<span class="entry-time" id="' + id + '-time">' + formatTime(entry.timestamp) + '</span>' +
        '<span class="entry-method ' + entry.method + '" id="' + id + '-method">' + entry.method + '</span>' +
        '<span class="entry-url" id="' + id + '-url" title="' + escapeHtml(entry.url) + '">' + escapeHtml(urlPath) + '</span>' +
        '<span class="entry-status ' + statusClass(entry.statusCode) + '" id="' + id + '-status">' + entry.statusCode + '</span>' +
        '<span class="entry-duration" id="' + id + '-duration">' + entry.durationMs + 'ms</span>' +
        '<span class="entry-badge ' + badgeClass(entry.classLabel) + '" id="' + id + '-badge">' + escapeHtml(entry.classLabel) + '</span>' +
      '</div>' +
      '<div class="entry-details" id="' + id + '-details">' +
        '<div class="detail-actions" id="' + id + '-actions"><button class="btn btn-copy-curl" id="' + id + '-copy-curl">Copy as curl</button></div>' +
        renderCredentialLinks(entry.credentials, entry.credentialLabels, id + "-credentials") +
        (entry.decoded ? '<div class="detail-section" id="' + id + '-decoded"><h3 id="' + id + '-decoded-title">Decoded</h3>' + renderDecoded(entry.decoded, id + "-decoded") + '</div>' : '') +
        detailSection(id + "-request-headers", "Request headers", renderHeaders(entry.requestHeaders)) +
        (entry.requestBody ? detailSection(id + "-request-body", entry.requestTruncated ? "Request body (start only)" : "Request body", escapeHtml(entry.requestBody)) : '') +
        detailSection(id + "-response-headers", "Response headers", renderHeaders(entry.responseHeaders)) +
        (entry.responseBody ? detailSection(id + "-response-body", entry.responseTruncated ? "Response body (start only)" : "Response body", escapeHtml(entry.responseBody)) : '') +
      '</div>';

    if (expandedEntries.has(entry.id)) el.classList.add("expanded");
    el.querySelector(".entry-header").addEventListener("click", function () {
      if (el.classList.toggle("expanded")) expandedEntries.add(entry.id);
      else expandedEntries.delete(entry.id);
    });

    el.querySelector(".btn-copy-curl").addEventListener("click", function (e) {
      e.stopPropagation();
      var curl = generateCurl(entry);
      navigator.clipboard.writeText(curl).then(function () {
        var btn = e.target;
        btn.textContent = "Copied!";
        setTimeout(function () { btn.textContent = "Copy as curl"; }, 1500);
      });
    });

    return el;
  }

  function renderFlowTimeline(visible) {
    var flowGroups = {};
    var flowOrder = [];
    var standalone = [];

    for (var i = 0; i < visible.length; i++) {
      var entry = visible[i];
      if (entry.flowId) {
        if (!flowGroups[entry.flowId]) {
          flowGroups[entry.flowId] = [];
          flowOrder.push(entry.flowId);
        }
        flowGroups[entry.flowId].push(entry);
      } else {
        standalone.push(entry);
      }
    }

    var frag = document.createDocumentFragment();

    flowOrder.reverse();
    standalone.reverse();

    for (var f = 0; f < flowOrder.length; f++) {
      frag.appendChild(renderFlowGroup(flowOrder[f], flowGroups[flowOrder[f]]));
    }

    for (var s = 0; s < standalone.length; s++) {
      frag.appendChild(renderEntry(standalone[s]));
    }

    return frag;
  }

  function renderFlowGroup(flowId, flowEntries) {
    var group = document.createElement("div");
    group.className = "flow-group";
    var groupId = idPart(flowId);
    group.id = groupId;
    group.dataset.flowId = flowId;
    if (collapsedFlows.has(flowId)) group.classList.add("collapsed");

    var header = document.createElement("div");
    header.className = "flow-header";
    header.id = groupId + "-header";
    header.innerHTML =
      '<span class="flow-type" id="' + groupId + '-type"></span>' +
      '<span class="flow-time" id="' + groupId + '-time"></span>' +
      '<span class="flow-count" id="' + groupId + '-count"></span>' +
      '<span class="flow-toggle" id="' + groupId + '-toggle"></span>';

    var entriesContainer = document.createElement("div");
    entriesContainer.className = "flow-entries";
    entriesContainer.id = groupId + "-entries";
    for (var k = 0; k < flowEntries.length; k++) {
      entriesContainer.appendChild(renderEntry(flowEntries[k]));
    }

    header.addEventListener("click", function () {
      var collapsed = group.classList.toggle("collapsed");
      if (collapsed) collapsedFlows.add(flowId);
      else collapsedFlows.delete(flowId);
      group.querySelector(".flow-toggle").textContent = collapsed ? "▶" : "▼";
    });

    group.appendChild(header);
    group.appendChild(entriesContainer);
    updateFlowHeader(group, flowEntries);
    return group;
  }

  function updateFlowHeader(group, flowEntries) {
    var flowType = "Flow";
    for (var j = 0; j < flowEntries.length; j++) {
      if (flowEntries[j].classLabel.startsWith("VP")) { flowType = "VP flow"; break; }
      if (flowEntries[j].classLabel.startsWith("VCI")) { flowType = "VCI flow"; break; }
    }
    var firstTime = formatTime(flowEntries[0].timestamp);
    var lastTime = formatTime(flowEntries[flowEntries.length - 1].timestamp);
    group.querySelector(".flow-type").textContent = flowType;
    group.querySelector(".flow-time").textContent = firstTime === lastTime ? firstTime : firstTime + " – " + lastTime;
    group.querySelector(".flow-count").textContent = flowEntries.length + " requests";
    group.querySelector(".flow-toggle").textContent = group.classList.contains("collapsed") ? "▶" : "▼";
  }

  // The timeline lists flow groups newest first, then the entries without a
  // flow, newest first. A new entry joins its group or starts one at the top.
  function addToTimeline(entry) {
    if (!entry.flowId) {
      entriesEl.insertBefore(renderEntry(entry), entriesEl.querySelector(":scope > .entry"));
      return;
    }
    var flowEntries = entries.filter(function (e) { return e.flowId === entry.flowId && isVisible(e); });
    var group = entriesEl.querySelector('.flow-group[data-flow-id="' + CSS.escape(entry.flowId) + '"]');
    if (!group) {
      entriesEl.insertBefore(renderFlowGroup(entry.flowId, flowEntries), entriesEl.firstChild);
      return;
    }
    group.querySelector(".flow-entries").appendChild(renderEntry(entry));
    updateFlowHeader(group, flowEntries);
  }

  function renderEntries() {
    entriesEl.innerHTML = "";
    var visible = entries.filter(isVisible);
    if (visible.length === 0) {
      entriesEl.appendChild(emptyEl);
      emptyEl.style.display = "";
      return;
    }
    emptyEl.style.display = "none";

    if (timelineView) {
      entriesEl.appendChild(renderFlowTimeline(visible));
    } else {
      for (var i = visible.length - 1; i >= 0; i--) {
        entriesEl.appendChild(renderEntry(visible[i]));
      }
    }
  }

  function addEntry(entry) {
    // The stream and the entry list overlap after every (re)connect.
    if (entry.id <= clearedThroughID || entries.some(function (e) { return e.id === entry.id; })) return;
    entries.push(entry);
    if (entries.length > entriesLimit) {
      entries.splice(0, entries.length - entriesLimit);
      renderEntries();
      return;
    }
    if (!isVisible(entry)) return;

    if (emptyEl.style.display !== "none") {
      emptyEl.style.display = "none";
      entriesEl.innerHTML = "";
    }
    if (timelineView) {
      addToTimeline(entry);
      return;
    }
    entriesEl.insertBefore(renderEntry(entry), entriesEl.firstChild);
  }

  // SSE does not replay traffic from before the subscription or during a disconnect, so
  // every connection fetches the existing entries.
  function syncEntries() {
    return fetch("api/entries")
      .then(function (r) {
        var limit = parseInt(r.headers.get("X-Entries-Limit"), 10);
        if (limit > 0) entriesLimit = limit;
        return r.json();
      })
      .then(function (data) {
        if (!data || data.length === 0) return;
        var known = {};
        for (var i = 0; i < entries.length; i++) {
          known[entries[i].id] = true;
        }
        var added = false;
        for (var j = 0; j < data.length; j++) {
          if (data[j].id <= clearedThroughID) continue;
          if (!known[data[j].id]) {
            entries.push(data[j]);
            added = true;
          }
        }
        if (!added) return;
        // The timeline stores entries oldest first. The list renders them reversed.
        entries.sort(function (a, b) { return a.id - b.id; });
        if (entries.length > entriesLimit) entries.splice(0, entries.length - entriesLimit);
        renderEntries();
      })
      .catch(function (err) {
        console.error("Failed to load entries:", err);
      });
  }

  function connectSSE() {
    const es = new EventSource("api/stream");

    es.onmessage = function (event) {
      try {
        const entry = JSON.parse(event.data);
        addEntry(entry);
      } catch (err) {
        console.error("Failed to parse SSE event:", err);
      }
    };

    es.onopen = function () {
      statusEl.textContent = "Connected";
      statusEl.className = "status";
      syncEntries();
    };

    es.onerror = function () {
      statusEl.textContent = "Disconnected";
      statusEl.className = "status disconnected";
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }

  connectSSE();
})();
