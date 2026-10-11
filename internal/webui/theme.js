// The theme of every eudi-dev page. The pages share the origin of the wallet,
// so one stored choice applies to all of them. "light" and "dark" are a
// choice. Without one the page follows the system preference. The script
// runs in the head, so the page paints in its theme from the start.
(function () {
  'use strict';

  var KEY = 'eudi-dev-theme';
  var systemLight = window.matchMedia('(prefers-color-scheme: light)');

  function chosen() {
    try {
      var value = localStorage.getItem(KEY);
      return value === 'light' || value === 'dark' ? value : null;
    } catch (e) {
      return null;
    }
  }

  function apply(theme) {
    if (theme === 'light') document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
  }

  function current() {
    return chosen() || (systemLight.matches ? 'light' : 'dark');
  }

  apply(current());
  systemLight.addEventListener('change', function () { apply(current()); });

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-theme-toggle]').forEach(function (button) {
      button.addEventListener('click', function () {
        var next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        try {
          localStorage.setItem(KEY, next);
        } catch (e) {
          // Without storage the choice lasts until the page reloads.
        }
        apply(next);
      });
    });
  });
})();
