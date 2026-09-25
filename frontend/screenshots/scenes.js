/**
 * The screenshot catalogue.
 *
 * One entry per picture the site uses: a name, the storage the application
 * should wake up with, how to reach the view, and anything the stubbed bridge
 * should answer differently from the fixtures.
 *
 * Every scene exists in both themes, because the site offers both and a
 * half-dressed gallery looks unfinished. They are generated in pairs rather
 * than written twice, so the pair cannot drift.
 *
 * The demo takes its opening state from here too (vite.demo.config.js), which
 * is what stops the demo and the pictures of it disagreeing.
 *
 * Note on `nav`: the active view is a plain store, not a persisted setting, so
 * it cannot be seeded — the runner clicks the sidebar. The indices are the
 * order of the buttons in App.svelte.
 */

const THEMES = ['dark', 'light'];

export const NAV = {
  logs: 0,
  dashboard: 1,
  alerts: 2,
  notify: 3,
  simulator: 4,
};

/** Storage the application reads at startup. Values are strings, as stored. */
function storage({ theme, locale = 'en', anonymous = false }) {
  return {
    'syslogstudio-theme': theme,
    'syslogstudio-locale': locale,
    'syslogstudio-anonymous': anonymous ? 'true' : 'false',
  };
}

/**
 * `click` and `settle` are instructions to the screenshot runner rather than to
 * the application: what to press once the page has loaded, and how long to wait
 * before the shutter. They live here so a picture's recipe sits beside the
 * state it needs.
 *
 * `expect` is the guard. A scene that needs messages and does not get them
 * photographs an empty list with "no messages" across it — which is worse than
 * no picture, because it ships and nobody notices. Saying what must be on
 * screen turns that into a failed run.
 */
const BASE = [
  {
    name: 'live',
    title: 'Messages arriving',
    nav: NAV.logs,
    // A feed, so the counters move: a picture of a receiver that is running,
    // not a picture of a screenshot of one.
    feed: { from: 'live', everyMs: 900 },
    settle: 2600,
    expect: { selector: '.log-row', atLeast: 20 },
  },
  {
    name: 'message-detail',
    title: 'One message, in full',
    nav: NAV.logs,
    // A feed, because there is nothing to click on until messages have
    // arrived: the list is filled entirely from events.
    feed: { from: 'live', everyMs: 2000 },
    click: '.log-row',
    clickNth: 12,
    settle: 900,
    expect: { selector: '.log-row', atLeast: 13 },
  },
  {
    name: 'dashboard',
    title: 'Severity, sources and rate',
    nav: NAV.dashboard,
    feed: { from: 'live', everyMs: 900 },
    settle: 2400,
  },
  {
    name: 'alerts',
    title: 'Alert rules and what they caught',
    nav: NAV.alerts,
    settle: 700,
  },
  {
    name: 'routing',
    title: 'Rules and destinations',
    nav: NAV.notify,
    settle: 800,
  },
  {
    name: 'simulator',
    title: 'The built-in traffic generator',
    nav: NAV.simulator,
    settle: 700,
  },
  {
    name: 'import',
    title: 'Importing a log file',
    nav: NAV.logs,
    // Two presses: Import in the toolbar, then the file chooser in the dialog.
    click: [
      { selector: '.action-btn', nth: 0 },
      { selector: '.modal .btn.primary' },
    ],
    // Choosing a file needs a dialog the browser does not have, so the scene
    // supplies the answer. Everything after it — the counts, what was inferred,
    // the sample — is the real component reading the real preview fixture.
    bindings: { SelectLogFile: '/var/log/collector/nightly-archive.log' },
    settle: 900,
    expect: { selector: '.modal .sev', atLeast: 5 },
  },
  {
    name: 'import-format',
    title: 'Describing the format of a file',
    nav: NAV.logs,
    // Import, then the file chooser, then the format panel.
    click: [
      { selector: '.action-btn', nth: 0 },
      { selector: '.modal .btn.primary' },
      { selector: '.modal .disclosure' },
      // A mode with fields of its own, since a picture of the automatic one
      // shows only the two checkboxes that are on screen anyway.
      { selector: '.modal .format select', value: 'custom' },
      // String.raw, because a pattern written with single backslashes in an
      // ordinary JS string quietly loses them: '\S' is just 'S'.
      {
        selector: '.modal .format input.mono',
        text: String.raw`^(?P<time>\S+ \S+)\s+(?P<level>\w+)\s+(?P<msg>.*)$`,
      },
    ],
    bindings: { SelectLogFile: '/var/log/collector/nightly-archive.log' },
    settle: 900,
    expect: { selector: '.modal .format input.mono', atLeast: 1 },
  },
  {
    name: 'anonymous',
    title: 'Anonymous mode, for sharing a screen',
    nav: NAV.logs,
    anonymous: true,
    // Without a feed there is nothing to anonymise, and the picture meant to
    // show masking showed an empty list instead.
    feed: { from: 'live', everyMs: 900 },
    settle: 2600,
    expect: { selector: '.log-row', atLeast: 20 },
  },
];

export function buildScenes() {
  const out = [];
  for (const base of BASE) {
    for (const theme of THEMES) {
      out.push({
        ...base,
        name: `${base.name}-${theme}`,
        theme,
        seeds: storage({ theme, anonymous: base.anonymous }),
        bindings: base.bindings || {},
        events: base.events || [],
        feed: base.feed || null,
        latency: base.latency || {},
        expect: base.expect || null,
      });
    }
  }
  return out;
}

export const SCENES = buildScenes();
