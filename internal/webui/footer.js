// The footer of every eudi-dev page: the version or the theme's product,
// release channel, imprint and sponsor link. A page passes its wallet
// configuration or decoder metadata to window.eudiFooter. A page without its
// own script lists candidate URLs in data-config. The first one that answers
// is used, because the imprint page is served by both the wallet and the
// decoder.
(function () {
  'use strict';

  var CHANNELS = { alpha: 'Alpha', beta: 'Beta', rc: 'Release candidate' };

  var product = null;
  var shown = null;

  // With a product from the theme, the footer shows the product and its
  // version instead of the eudi-dev version and its release channel.
  function renderVersion(version) {
    var label = document.getElementById('footer-prerelease');
    if (product) {
      var name = document.createElement(product.url ? 'a' : 'span');
      name.id = 'footer-product';
      name.textContent = product.name;
      if (product.url) {
        name.href = product.url;
        name.target = '_blank';
        name.rel = 'noopener';
      }
      version.replaceChildren(name);
      if (product.version) version.append(' ' + product.version);
      if (label) label.hidden = true;
      return;
    }
    version.textContent = 'eudi-dev ' + shown;
    var prerelease = /-(alpha|beta|rc)\b/i.exec(shown);
    if (label) {
      label.textContent = prerelease ? CHANNELS[prerelease[1].toLowerCase()] : '';
      label.title = 'A prerelease for testing. It is not stable yet.';
      label.hidden = !prerelease;
    }
  }

  function render(config) {
    if (!config) return;
    var version = document.getElementById('footer-version');
    if (version && config.version) {
      shown = config.version;
      renderVersion(version);
    }
    var imprint = document.getElementById('imprint-link');
    // The link gets its target only when the server has an imprint page.
    if (imprint && config.imprint) {
      imprint.href = imprint.dataset.href;
      imprint.hidden = false;
    }
    var sponsor = document.getElementById('sponsor-link');
    if (sponsor) sponsor.hidden = !(config.demo === true || (config.demo && config.demo.enabled));
  }

  window.eudiFooter = render;

  function load(sources) {
    if (sources.length === 0) return;
    fetch(sources[0])
      .then(function (resp) {
        if (!resp.ok) throw new Error(resp.status);
        return resp.json();
      })
      .then(render)
      .catch(function () { load(sources.slice(1)); });
  }

  // theme/texts.json is served next to this script on every page.
  var script = document.currentScript;
  if (script) {
    fetch(new URL('theme/texts.json', script.src))
      .then(function (resp) { return resp.ok ? resp.json() : {}; })
      .then(function (texts) {
        product = texts.product || null;
        var version = document.getElementById('footer-version');
        if (product && version && shown) renderVersion(version);
      })
      .catch(function () {});
  }

  var sources = script && script.getAttribute('data-config');
  if (sources) load(sources.split(' '));
})();
