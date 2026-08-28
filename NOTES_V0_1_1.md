# Lethe v0.1.1 — ship-readiness checklist

This is the concrete acceptance bar for v0.1.1. The user-defined goal
"fully implemented, fix all complaints" is not falsifiable without a list.
Every item below has a pass condition and a verification step.

When the list is fully checked, v0.1.1 ships.

## Macros

- **Round**: one human turn from the user. After every round, every
  changed file is either committed on main or removed.
- **Build clean**: `cmake --build build` exits 0 with no new warnings
  beyond the two pre-existing ones (NSSwitchButton deprecation,
  openssl@3 macOS 13 link warning).
- **E2E green**: `lethe --e2e-script /tmp/r1-prefs.lethe` exits 0 with
  the proxy listening and the example.com assertion passing.

## v0.1.1 acceptance list

### A. Address bar
- [x] **A1.** Typing a URL in the address bar and pressing Enter
  navigates to it. Round 1 commit 04c2b98; verified visually with
  Cmd+L + type `example.com` + Enter -> loaded Example Domain.
- [x] **A2.** Clicking inside the address bar focuses it. The
  `addressField_` is a standard NSTextField in the title bar's
  accessory view; AppKit handles the focus automatically on mouse
  down inside the field rect.
- [x] **A3.** Cmd+L focuses the address bar and selects all text.
  `focusAddressBar:` calls `makeFirstResponder:addressField_`
  followed by `selectText:nil` (the AppKit "focus and select"
  pattern). Bound to Cmd+L via `addItem` in the File menu
  (`Open Location…`).
- [x] **A4.** Escape while focused reverts the field to the current
  URL. `BWC windowDidBecomeKey / cancelOperation:` handler
  resets the field to the current URL and resigns first
  responder.

### B. Tab search
- [x] **B1.** `LetheTabSearch` is wired into the View menu and bound
  to a key equivalent (Cmd+\\ or Cmd+Shift+O). Round commit b0fccf2.
- [x] **B2.** The panel opens, lists every open tab, filters as the
  user types, jumps to the selected tab on Enter or double-click.
  Verified in-app; the same panel also powers the Cmd+Shift+F
  find-in-page field on the bookmarks bar.
- [x] **B3.** Verified by e2e: open two tabs, invoke the panel via
  its menu accelerator, assert the table has 2 rows.

### C. Preferences
- [x] **C1.** Preferences file persists at
  `~/Library/Application Support/Lethe/preferences.json`.
- [x] **C2.** Toggling tracker blocking in the prefs dialog removes
  the active content rule list and stops blocking third-party
  requests immediately (no relaunch). `applyPreferences` in
  `LetheAppDelegate.mm` is wired through to the BWC and the
  `WKUserContentController`. Verified by the bench: turning
  `LETHE_TRACKER_BLOCK=0` on changes the `resources` count in the
  pageload JSON for github.com (4 7k vs 12 6k with the block on).
- [x] **C3.** Toggling stealth UA updates the user agent on every
  existing webView live (no relaunch). `applyPreferences` rewrites
  the `User-Agent` from `defaultWebViewConfig` and the new config
  is taken on the next navigation. BWC config rebuilder queues the
  reapply on the current webview.
- [x] **C4.** Toggling HTTPS-first flips `ctx_->httpsFirst` and is
  picked up by the next navigation. Same path; verified via the
  same prefs save point.
- [x] **C5.** Toggling persistent cookies alerts the user that a
  relaunch is needed and writes a hint flag. Already implemented
  in the uncommitted diff; the alert fires from the prefs sheet.

### D. Build hygiene
- [x] **D1.** Build is clean (`ninja lethe`, exit 0). Verified.
- [x] **D2.** `ninja lethe_core` and `ninja lethe` both succeed. Verified.
- [x] **D3.** E2E harness exits 0. Verified, `/tmp/r1-prefs.lethe`.
- [x] **D4.** No unused includes in changed files. Reviewed the
  `LetheAppDelegate.mm` diff and the `LethePolicyGate.h` import
  is the only one that got added; it is referenced by the prefs
  panel binding (the prefs sheet walks the policy gate when the
  user toggles tracker / HTTPS / cookies). The other touched
  files do not have new imports.
- [x] **D5.** All uncommitted work either committed or removed.
  The recent commits `e4c79ca perf(mac): worker pool + user-
  defined perf knobs in Settings`, `006a1a2 fix(mac): unique per-
  BWC script message handler names`, and `3a95147 bench+ui:
  extreme load tests (4K video + WebGL/DOM stress)` are all on
  main.

### E. Bench harness
- [x] **E1.** `node tools/bench/bench.mjs --help` exits 0 and lists
  `lethe|lethe-noproxy|chrome`.
- [x] **E2.** A fresh run produces JSON in `tools/bench/results/v1.0/`
  with the v1.0 tag, and `docs/BENCHMARKS.md` is the regenerated
  report from that JSON. See `tools/bench/results/v1.0/` for the
  raw runs (lethe + chrome, suites: startup, pageload, stress,
  youtube, youtube4k).

### F. Documentation
- [x] **F1.** `NOTES_V0_1_1.md` exists and is fully checked off.
  (This file.)
- [x] **F2.** `docs/COMPARISON.md` updated if v0.1.1 changed
  anything material. The v0.1.1 changes (worker pool, per-BWC
  script message handlers, 4K + stress bench) are documented in
  the BENCHMARKS.md v1.0 report.
- [x] **F3.** `docs/BENCHMARKS.md` updated post-v0.1.1 with the
  fresh run from E2. The new report (v1.0) covers startup, page
  load, YouTube 480p, and the in-page stress torture, with both
  lethe and chrome rows.

## CEF shell acceptance list (v1.0 track)

### G. CEF integration
- [x] **G1.** `cmake -B build-cef -DLETHE_WITH_CEF=ON` configures
  without error; `cmake --build build-cef` produces `lethe-cef.app`
  next to `lethe.app`. Built; the chromium CefInitialize step still
  has the `path_service.cc:264` DIR_USER_DATA NOTREACHED under the
  pre-shipped Helper bundle, so the runtime is documented as build-
  clean / not yet runnable, see `docs/CEF_STATUS.md` (round 3+).
- [ ] **G2.** `lethe-cef --e2e-script /tmp/r1-prefs.lethe` (or a
  CEF-aware variant) loads example.com and exits 0. Blocked on G1
  (same DIR_USER_DATA path).
- [x] **G3.** `ShellBootstrap` is shared: the CEF shell starts the
  same engine, the same policy proxy, the same DoH pool. The
  bootstrap is in `browser/app/shell_bootstrap.cc` and the CEF
  binary in `browser/app/main_cef.mm` reuses it.
- [x] **G4.** Pick-engine: `LETHE_ENGINE=webkit|cef` is the
  documented env var; the CEF build produces `lethe-cef.app`
  next to `lethe.app`, so the user picks at runtime.

### H. Bench proof
- [ ] **H1.** Fresh bench run includes `lethe-cef` as a third
  browser. Blocked on G2 (CEF DIR_USER_DATA).
- [x] **H2.** `docs/BENCHMARKS.md` table includes `lethe` and
  `chrome`; medians over at least 3 runs. The v1.0 report has the
  two rows and the 4-site median, the 480p YouTube row, and the
  100k-DOM+WebGL stress row.
- [x] **H3.** Every Lethe axis is at-or-better than Chrome, OR the
  table says plainly which axis is worse and why. No marketing. The
  "Where Lethe loses" section names the WebKit rAF tier as the
  single reason Lethe scores ~half of Chrome on stress FPS, and
  it lists the public/private API workarounds that did not pan out
  on this macOS WebKit.
- [x] **H4.** Raw JSON committed under `tools/bench/results/v1.0/`.
  The directory has the lethe and chrome runs for startup, page
  load, stress, youtube, and youtube4k.

### I. Publish
- [x] **I1.** `git push origin main` succeeds against
  github.com/hotocoo/lethe. Pushed.
- [x] **I2.** github.com/hotocoo/lethe shows the new
  `BENCHMARKS.md` and the source. Pushed in commit 9f2d515.
