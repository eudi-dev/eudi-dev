// Every dialog title gets three actions. The command button shows the curl
// and CLI command for the dialog's action, or the YAML for a file, with its
// current values. The size button switches the dialog between almost full
// screen and its normal size. The close button closes the dialog.
(function () {
  'use strict';

  const ICON_COMMAND = '<svg viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5.5 4.5 2 8l3.5 3.5M10.5 4.5 14 8l-3.5 3.5"/></svg>';
  const ICON_MAXIMIZE = '<svg viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2.5h4v4M6.5 13.5h-4v-4M13.5 2.5 9 7M2.5 13.5 7 9"/></svg>';
  const ICON_CLOSE = '<svg viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M4 4l8 8M12 4l-8 8"/></svg>';
  const ICON_RESTORE = '<svg viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M13.5 6.5h-4v-4M2.5 9.5h4v4M9.5 6.5 14 2M6.5 9.5 2 14"/></svg>';

  // The commands use the page's own wallet URL, including a path prefix.
  const walletBase = new URL('.', document.baseURI);

  function walletURL(path) {
    return new URL(path || '', walletBase).href;
  }

  function remoteURL() {
    return walletBase.href.replace(/\/$/, '');
  }

  function shellQuote(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
  }

  // heredoc passes content on stdin. Its delimiter is a line the content
  // doesn't have, so pasted text can't end it early.
  function heredoc(content) {
    const lines = new Set(String(content).split('\n'));
    let delimiter = 'EOF';
    for (let n = 2; lines.has(delimiter); n++) delimiter = 'EOF' + n;
    return " <<'" + delimiter + "'\n" + content + '\n' + delimiter;
  }

  // curl builds a curl command. A JSON body goes into a heredoc, so it needs no
  // quoting and stays readable.
  function curl(method, path, body, headers) {
    const parts = ['curl -sS -X ' + method + ' ' + shellQuote(walletURL(path))];
    for (const [name, value] of Object.entries(headers || {})) {
      parts.push('-H ' + shellQuote(name + ': ' + value));
    }
    if (body === undefined) return parts.join(' \\\n  ');
    parts.push("-H 'Content-Type: application/json'");
    parts.push('--data-binary @-');
    return parts.join(' \\\n  ') + heredoc(JSON.stringify(body, null, 2));
  }

  // cli joins a command and its flags. Each flag is [name, value] or [name] for
  // a boolean. Values are quoted.
  function cli(command, flags) {
    const parts = [command];
    for (const [name, value] of flags) {
      parts.push(value === undefined ? name : name + ' ' + shellQuote(value));
    }
    return parts.join(' \\\n  ');
  }

  // A plain YAML scalar is read back as the same text. Anything else is
  // quoted the JSON way, which YAML reads as a double quoted string.
  function yamlString(text) {
    const plain = /^[A-Za-z_][\w .\/@:+-]*$/.test(text) && !/: |:$| $/.test(text) &&
      !/^(true|false|null|yes|no|on|off|y|n)$/i.test(text);
    return plain ? text : JSON.stringify(text);
  }

  function yamlScalar(value) {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'string') return yamlString(value);
    return String(value);
  }

  function isBlock(value) {
    return value !== null && typeof value === 'object' && Object.keys(value).length > 0;
  }

  // A short list of scalars or of such lists stays on one line, like
  // always_disclosed: [employee_id].
  function yamlFlow(value) {
    if (!Array.isArray(value)) return null;
    const items = [];
    for (const item of value) {
      if (Array.isArray(item)) {
        const inner = yamlFlow(item);
        if (inner === null) return null;
        items.push(inner);
      } else if (isBlock(item)) {
        return null;
      } else {
        items.push(item !== null && typeof item === 'object' ? '{}' : yamlScalar(item));
      }
    }
    const flow = '[' + items.join(', ') + ']';
    return flow.length <= 72 ? flow : null;
  }

  function yamlValue(value, indent) {
    if (!isBlock(value)) {
      if (Array.isArray(value)) return ' []';
      if (value !== null && typeof value === 'object') return ' {}';
      return ' ' + yamlScalar(value);
    }
    const flow = yamlFlow(value);
    if (flow !== null) return ' ' + flow;
    return '\n' + yamlBlock(value, indent + 2);
  }

  function yamlBlock(value, indent) {
    const pad = ' '.repeat(indent);
    if (Array.isArray(value)) {
      return value.map(item => {
        if (isBlock(item) && !Array.isArray(item)) {
          return pad + '- ' + yamlBlock(item, indent + 2).slice(indent + 2);
        }
        return pad + '-' + yamlValue(item, indent);
      }).join('\n');
    }
    return Object.entries(value).map(([key, item]) => pad + yamlString(key) + ':' + yamlValue(item, indent)).join('\n');
  }

  // yaml writes a JSON value as a YAML document for a file, such as a
  // template or a relying party in a ConfigMap.
  function yaml(value) {
    return (isBlock(value) ? yamlBlock(value, 0) : yamlScalar(value)) + '\n';
  }

  const builders = new WeakMap();
  const states = new WeakMap();

  function stateOf(dialog) {
    if (!states.has(dialog)) states.set(dialog, { open: false, mode: 'curl', maximized: false });
    return states.get(dialog);
  }

  // setCommand registers the command builder of a dialog, or removes it when
  // build is null. build returns { curl, cli, note, cliNote, yaml, yamlNote,
  // docs }. yaml is the content of a file the wallet reads at startup. docs is
  // { text, label, href } and links the documentation after the note. It runs only
  // while the panel is open. It throws an Error for unusable form values.
  function setCommand(dialog, build) {
    if (build) builders.set(dialog, build);
    else builders.delete(dialog);
    decorate(dialog);
    refresh(dialog);
  }

  // decorate adds the actions in front of the title and the command panel
  // after it. The title stays in place, so it keeps the focus. A dialog
  // without a title of its own gets both at its start.
  function decorate(dialog) {
    if (dialog.querySelector(':scope > .dialog-actions')) return;
    const title = dialog.querySelector(':scope > .consent-title');
    const id = dialog.id;
    const actions = document.createElement('span');
    actions.className = 'dialog-actions';
    actions.id = id + '-actions';
    actions.innerHTML =
      '<button type="button" class="dialog-action" id="' + id + '-command-toggle" aria-expanded="false" aria-controls="' + id + '-command" title="API and CLI command" aria-label="API and CLI command">' + ICON_COMMAND + '</button>' +
      '<button type="button" class="dialog-action" id="' + id + '-size" aria-pressed="false" title="Maximize" aria-label="Maximize">' + ICON_MAXIMIZE + '</button>' +
      '<button type="button" class="dialog-action" id="' + id + '-close" title="Close" aria-label="Close">' + ICON_CLOSE + '</button>';
    if (title) title.before(actions);
    else dialog.prepend(actions);

    const panel = document.createElement('div');
    panel.className = 'dialog-command';
    panel.id = id + '-command';
    panel.hidden = true;
    panel.innerHTML =
      '<div class="dialog-command-head" id="' + id + '-command-head">' +
        '<div class="claims-mode dialog-command-mode" role="radiogroup" aria-label="Command type" id="' + id + '-command-mode">' +
          '<label class="form-checkbox" id="' + id + '-command-curl-label"><input type="radio" name="' + id + '-command-mode" id="' + id + '-command-curl" value="curl" checked> curl</label>' +
          '<label class="form-checkbox" id="' + id + '-command-cli-label"><input type="radio" name="' + id + '-command-mode" id="' + id + '-command-cli" value="cli"> CLI</label>' +
          '<label class="form-checkbox" id="' + id + '-command-yaml-label"><input type="radio" name="' + id + '-command-mode" id="' + id + '-command-yaml" value="yaml"> YAML</label>' +
        '</div>' +
        '<span class="dialog-command-label" id="' + id + '-command-label">curl</span>' +
        '<button type="button" class="btn btn-sm" id="' + id + '-command-copy">Copy</button>' +
      '</div>' +
      '<pre class="dialog-command-text" id="' + id + '-command-text" tabindex="0"></pre>' +
      '<p class="dialog-command-note" id="' + id + '-command-note" hidden></p>' +
      '<p class="dialog-command-note" id="' + id + '-command-docs" hidden><span id="' + id + '-command-docs-text"></span> ' +
        '<a id="' + id + '-command-docs-link" target="_blank" rel="noopener"></a></p>';
    (title || actions).after(panel);

    const state = stateOf(dialog);
    actions.querySelector('#' + id + '-command-toggle').addEventListener('click', () => {
      state.open = !state.open;
      refresh(dialog);
    });
    const size = actions.querySelector('#' + id + '-size');
    size.addEventListener('click', () => {
      state.maximized = !state.maximized;
      applySize(dialog, size);
    });
    applySize(dialog, size);
    // The close action presses the dialog's own close button, so the dialog
    // closes the way it always does.
    actions.querySelector('#' + id + '-close').addEventListener('click', () => {
      const close = closeButton(dialog);
      if (close) close.click();
    });
    panel.querySelectorAll('input[type="radio"]').forEach(radio => {
      radio.addEventListener('change', () => {
        state.mode = radio.value;
        refresh(dialog);
      });
    });
    const copy = panel.querySelector('#' + id + '-command-copy');
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(panel.querySelector('.dialog-command-text').textContent);
        copy.textContent = 'Copied';
        setTimeout(() => { copy.textContent = 'Copy'; }, 1200);
      } catch (e) { /* The clipboard API may be unavailable. */ }
    });
    refresh(dialog);
  }

  function applySize(dialog, button) {
    const maximized = stateOf(dialog).maximized;
    dialog.classList.toggle('dialog-maximized', maximized);
    button.setAttribute('aria-pressed', String(maximized));
    const label = maximized ? 'Restore size' : 'Maximize';
    button.title = label;
    button.setAttribute('aria-label', label);
    button.innerHTML = maximized ? ICON_RESTORE : ICON_MAXIMIZE;
  }

  // closeButton is the dialog's visible button marked data-dialog-close. A
  // pending consent request has none, because it needs Approve or Deny.
  function closeButton(dialog) {
    return Array.from(dialog.querySelectorAll('[data-dialog-close]'))
      .find(button => !button.hidden && !button.disabled && !button.closest('[hidden]')) || null;
  }

  function refresh(dialog) {
    const toggle = dialog.querySelector(':scope > .dialog-actions .dialog-action[aria-controls]');
    const panel = dialog.querySelector(':scope > .dialog-command');
    if (!toggle || !panel) return;
    dialog.querySelector('#' + dialog.id + '-close').hidden = !closeButton(dialog);
    const build = builders.get(dialog);
    const state = stateOf(dialog);
    toggle.hidden = !build;
    toggle.setAttribute('aria-expanded', String(state.open && Boolean(build)));
    panel.hidden = !state.open || !build;
    if (panel.hidden) return;
    let command = null;
    let problem = '';
    try {
      command = build();
    } catch (e) {
      problem = e.message;
    }

    const modes = ['curl', 'cli', 'yaml'].filter(m => m === 'curl' || Boolean(command && command[m]));
    for (const m of ['cli', 'yaml']) {
      panel.querySelector('#' + dialog.id + '-command-' + m + '-label').hidden = !modes.includes(m);
    }
    panel.querySelector('.dialog-command-mode').hidden = modes.length < 2;
    panel.querySelector('.dialog-command-label').hidden = modes.length > 1;
    const mode = modes.includes(state.mode) ? state.mode : 'curl';
    panel.querySelector('input[value="' + mode + '"]').checked = true;
    panel.querySelector('.dialog-command-text').textContent = problem
      ? 'The form has a problem: ' + problem
      : command[mode];
    const note = panel.querySelector('.dialog-command-note');
    const noteText = command && { curl: command.note, cli: command.cliNote, yaml: command.yamlNote }[mode];
    note.textContent = noteText || '';
    note.hidden = !noteText;
    const docs = panel.querySelector('#' + dialog.id + '-command-docs');
    const doc = command && command.docs;
    docs.hidden = !doc;
    if (doc) {
      docs.querySelector('#' + dialog.id + '-command-docs-text').textContent = doc.text;
      const link = docs.querySelector('#' + dialog.id + '-command-docs-link');
      link.href = doc.href;
      link.textContent = doc.label;
    }
  }

  // Edits update an open command panel. After a redraw of the dialog's
  // content, decorate adds the actions again.
  function watch(dialog) {
    let pending = false;
    const schedule = () => {
      if (pending) return;
      pending = true;
      requestAnimationFrame(() => {
        pending = false;
        decorate(dialog);
        refresh(dialog);
      });
    };
    for (const type of ['input', 'change', 'click']) {
      dialog.addEventListener(type, (event) => {
        if (event.target.closest('.dialog-command, .dialog-actions')) return;
        schedule();
      });
    }
    new MutationObserver(schedule).observe(dialog, { childList: true });
  }

  document.querySelectorAll('.consent-overlay > .consent-dialog').forEach(dialog => {
    decorate(dialog);
    watch(dialog);
  });

  window.eudiDialogs = { setCommand, refresh, curl, cli, yaml, heredoc, shellQuote, walletURL, remoteURL };
})();
