// The footer of every eudi-dev page: version, release channel, imprint and
// sponsor link. A page passes its wallet configuration or decoder metadata to
// window.eudiFooter. A page without its own script lists candidate URLs in
// data-config. The first one that answers is used, because the imprint page
// is served by both the wallet and the decoder.
(function () {
  'use strict';

  var CHANNELS = { alpha: 'Alpha', beta: 'Beta', rc: 'Release candidate' };

  function render(config) {
    if (!config) return;
    var version = document.getElementById('footer-version');
    if (version && config.version) {
      version.textContent = 'eudi-dev ' + config.version;
      var prerelease = /-(alpha|beta|rc)\b/i.exec(config.version);
      var label = document.getElementById('footer-prerelease');
      if (label) {
        label.textContent = prerelease ? CHANNELS[prerelease[1].toLowerCase()] : '';
        label.title = 'A prerelease for testing. It is not stable yet.';
        label.hidden = !prerelease;
      }
    }
    var imprint = document.getElementById('imprint-link');
    if (imprint && config.imprint) imprint.hidden = false;
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

  var sources = document.currentScript && document.currentScript.getAttribute('data-config');
  if (sources) load(sources.split(' '));
})();
