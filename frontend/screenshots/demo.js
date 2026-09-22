/**
 * The browser demo's opening state.
 *
 * The same build as the screenshots — the real Svelte application with the
 * Wails bridge replaced by fixtures — but a person is going to use this one, so
 * three things differ from the screenshot director.
 *
 * NO localStorage.clear(). The demo is served from the same ORIGIN as the
 * project site, so they share one storage area: clearing it would throw away
 * the visitor's theme choice for the whole site every time they opened the
 * demo. Keys are seeded only when absent, which also means anything they change
 * here survives until they clear it themselves.
 *
 * NO pinned language. The screenshots pin English so the images are legible to
 * everyone; a demo should come up in the reader's own language, since being
 * translated into eight is one of the things worth showing.
 *
 * __SYSLOGSTUDIO_DEMO__ is set BEFORE the bundle evaluates. It is what makes
 * the bridge refuse the calls that would ask the operating system for something
 * a web page cannot have, instead of answering "ok" to a request to write a
 * file or open a socket.
 */

(function () {
  var SEEDS = __SEEDS__;

  window.__SYSLOGSTUDIO_DEMO__ = true;

  // A scene for the stubbed bridge to consult. No scripted events, and a FEED
  // so the message list fills while someone is looking at it — a log viewer
  // that never receives anything is a picture, not a demo.
  window.__SYSLOGSTUDIO_SCENE__ = {
    name: 'demo',
    bindings: {},
    events: [],
    feed: { from: 'live', everyMs: 1400 },
    latency: {
      // An answer that arrives in the same frame as the click reads as canned,
      // which is the impression a demo built on fixtures has to work against.
      GenerateCA: 900,
      GenerateServerCert: 700,
      GenerateCertificate: 700,
      TestNotifySink: 800,
    },
  };

  try {
    for (var k in SEEDS) {
      if (localStorage.getItem(k) === null) localStorage.setItem(k, SEEDS[k]);
    }

    // Arrive in the theme the visitor chose on the site.
    //
    // The demo is served from the same origin, so the site's own choice is
    // right there in storage — and coming up dark immediately after someone has
    // set the site to light reads as a different product rather than the same
    // one. Only on first run: after that the application's own theme toggle
    // owns it, which is the control a person would go looking for.
    if (localStorage.getItem('syslogstudio-demo-themed') === null) {
      var site = localStorage.getItem('site-theme');
      var wanted = site === 'light' || site === 'dark'
        ? site
        : (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
          ? 'light' : 'dark');
      localStorage.setItem('syslogstudio-theme', wanted);
      localStorage.setItem('syslogstudio-demo-themed', '1');
    }
  } catch (e) {
    // Private browsing. The application reads its defaults and the demo still
    // works, with less in it.
  }
})();
