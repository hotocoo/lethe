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
- [ ] **A2.** Clicking inside the address bar focuses it. Current
  status: visual test inconclusive; an AppKit click landed off the
  field. Verify by clicking the field rect directly. Owner: round 2.
- [ ] **A3.** Cmd+L focuses the address bar and selects all text.
  Round 1 verified focus lands; selection not yet verified.
- [ ] **A4.** Escape while focused reverts the field to the current
  URL. Existing `cancelOperation:` handler; needs a real Escape test.

### B. Tab search
- [ ] **B1.** `LetheTabSearch` is wired into the View menu and bound
  to a key equivalent (Cmd+\\ or Cmd+Shift+O). Currently dead code
  on disk: file added, not referenced. Owner: round 2.
- [ ] **B2.** The panel opens, lists every open tab, filters as the
  user types, jumps to the selected tab on Enter or double-click.
- [ ] **B3.** Verified by e2e: open two tabs, invoke the panel via
  its menu accelerator, assert the table has 2 rows.

### C. Preferences
- [x] **C1.** Preferences file persists at
  `~/Library/Application Support/Lethe/preferences.json`.
- [ ] **C2.** Toggling tracker blocking in the prefs dialog removes
  the active content rule list and stops blocking third-party
  requests immediately (no relaunch). The `applyPreferences` path
  in the uncommitted `LetheAppDelegate.mm` diff does this; needs
  visual verification. Owner: round 2.
- [ ] **C3.** Toggling stealth UA updates the user agent on every
  existing webView live (no relaunch). Same path; needs verification.
- [ ] **C4.** Toggling HTTPS-first flips `ctx_->httpsFirst` and is
  picked up by the next navigation. Same path; needs verification.
- [ ] **C5.** Toggling persistent cookies alerts the user that a
  relaunch is needed and writes a hint flag. Already implemented in
  the uncommitted diff; verify the alert fires.

### D. Build hygiene
- [x] **D1.** Build is clean (`ninja lethe`, exit 0). Verified.
- [x] **D2.** `ninja lethe_core` and `ninja lethe` both succeed. Verified.
- [x] **D3.** E2E harness exits 0. Verified, `/tmp/r1-prefs.lethe`.
- [ ] **D4.** No unused includes in changed files. The uncommitted
  `LetheAppDelegate.mm` added `#import "LethePolicyGate.h"` is used
  by the prefs panel wiring — verify the .h is actually referenced.
- [ ] **D5.** All uncommitted work either committed or removed.
  Status: `shell_bootstrap` + `main_mac.mm` refactor + `applyPreferences`
  still on disk, untested at the integration level. Owner: round 2.

### E. Bench harness
- [x] **E1.** `node tools/bench/bench.mjs --help` exits 0 and lists
  `lethe|lethe-noproxy|chrome`.
- [ ] **E2.** A fresh run produces JSON in `tools/bench/results/`
  with the v0.1.1 tag, and `tools/bench/report.mjs` regenerates
  the markdown table. Owner: round 2 (after v0.1.1 ships).

### F. Documentation
- [ ] **F1.** `NOTES_V0_1_1.md` exists and is fully checked off.
  (This file.)
- [ ] **F2.** `docs/COMPARISON.md` updated if v0.1.1 changed
  anything material.
- [ ] **F3.** `docs/BENCHMARKS.md` updated post-v0.1.1 with the
  fresh run from E2.

## CEF shell acceptance list (v1.0 track)

### G. CEF integration
- [ ] **G1.** `cmake -B build-cef -DLETHE_WITH_CEF=ON` configures
  without error; `cmake --build build-cef` produces `lethe-cef.app`
  next to `lethe.app`. Owner: round 3+.
- [ ] **G2.** `lethe-cef --e2e-script /tmp/r1-prefs.lethe` (or a
  CEF-aware variant) loads example.com and exits 0.
- [ ] **G3.** `ShellBootstrap` is shared: the CEF shell starts the
  same engine, the same policy proxy, the same DoH pool.
- [ ] **G4.** Pick-engine: either a runtime `LETHE_ENGINE` env var
  or two separate .app bundles, with the choice documented.

### H. Bench proof
- [ ] **H1.** Fresh bench run includes `lethe-cef` as a third browser.
- [ ] **H2.** `docs/BENCHMARKS.md` table includes `lethe`, `lethe-cef`,
  `chrome`; medians over at least 3 runs.
- [ ] **H3.** Every Lethe axis is at-or-better than Chrome, OR the
  table says plainly which axis is worse and why. No marketing.
- [ ] **H4.** Raw JSON committed under `tools/bench/results/v1.0/`.

### I. Publish
- [ ] **I1.** `git push origin main` succeeds against
  github.com/hotocoo/lethe. Owner: round 2 for the
  already-landed commits; round 3+ for the rest.
- [ ] **I2.** github.com/hotocoo/lethe shows the new `BENCHMARKS.md`
  and the source.
