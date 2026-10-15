// Every dialog title gets three actions. One shows the curl and CLI command
// for the dialog's action, with its current values. One makes the dialog
// almost full screen and back. The last one closes the dialog.
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

  const builders = new WeakMap();
  const states = new WeakMap();

  function stateOf(dialog) {
    if (!states.has(dialog)) states.set(dialog, { open: false, mode: 'curl', maximized: false });
    return states.get(dialog);
  }

  // setCommand registers the command builder of a dialog, or removes it when
  // build is null. build returns { curl, cli, note, cliNote }. It runs only
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
        '</div>' +
        '<span class="dialog-command-label" id="' + id + '-command-label">curl</span>' +
        '<button type="button" class="btn btn-sm" id="' + id + '-command-copy">Copy</button>' +
      '</div>' +
      '<pre class="dialog-command-text" id="' + id + '-command-text" tabindex="0"></pre>' +
      '<p class="dialog-command-note" id="' + id + '-command-note" hidden></p>';
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

    const hasCLI = Boolean(command && command.cli);
    panel.querySelector('.dialog-command-mode').hidden = !hasCLI;
    panel.querySelector('.dialog-command-label').hidden = hasCLI;
    const mode = hasCLI && state.mode === 'cli' ? 'cli' : 'curl';
    panel.querySelector('input[value="' + mode + '"]').checked = true;
    panel.querySelector('.dialog-command-text').textContent = problem
      ? 'The form has a problem: ' + problem
      : command[mode];
    const note = panel.querySelector('.dialog-command-note');
    const noteText = command && (mode === 'cli' ? command.cliNote : command.note);
    note.textContent = noteText || '';
    note.hidden = !noteText;
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

  window.eudiDialogs = { setCommand, refresh, curl, cli, heredoc, shellQuote, walletURL, remoteURL };
})();
