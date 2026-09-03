# CEF shell status (lethe-cef)

The v1.0 track: a second engine (Chromium Embedded Framework / Blink)
sharing the same ShellBootstrap, policy proxy, DoH pool, and VPN tunnel
as the WebKit shell. The goal is to give users a choice between the
system WebKit engine (default, lean) and Blink (heavier, but the same
engine family as Chrome).

## What works now

- **Builds clean.** `cmake -B build-cef -DLETHE_WITH_CEF=ON` and
  `cmake --build build-cef` produce `lethe-cef.app` next to
  `lethe.app`. The CEF framework and Helper are bundled into the .app.
- **CefInitialize succeeds.** The browser process boots, the policy
  proxy starts, the browser window is created, and the message loop
  runs.
- **RENDERER LAUNCHES (round-3 fix).** The blocker from rounds 1-2 is
  fixed. CEF 151 / Chromium 151 on macOS launches SOME child types from
  Chrome-style per-type helper bundles derived from the subprocess
  executable basename (`lethe_cef_helper (Renderer).app` etc.) and NOT
  from `CefSettings.browser_subprocess_path`. GPU and utility children
  used the generic path, which is why only the renderer was missing:
  its bundle never existed, the exec failed silently, and every
  navigation aborted with ERR_ABORTED. The CMake post-build step now
  creates `(Renderer)`, `(GPU)`, `(Plugin)` and `(Alerts)` bundles (APFS
  clones of the helper binary + a per-type Info.plist + a symlink to
  the shared framework) and ad-hoc signs the whole app.
- **Shared bootstrap.** Same engine init, same policy proxy, same DoH
  pool, same per-launch auth token. The CEF net stack is pointed at the
  local policy proxy via `OnBeforeCommandLineProcessing` (proxy-server).
- **Eval round-trip.** The renderer answers the browser's `lethe:eval`
  process messages (CefV8Context eval + reply), so the e2e / bench
  driver works against lethe-cef.
- **Clean browser teardown.** Initial native browser creation is deferred
  until the CEF/AppKit message loop is running. This avoids the macOS
  pre-run-loop native-window close path that could reach `DoClose` without
  ever delivering `OnBeforeClose`.
- **Native browser chrome + shortcuts.** CEF Alloy windows get Lethe's
  native macOS address/navigation chrome and subsequent CEF browsers join
  the selected native window tab group. Cmd+T/L/R/Shift+R/W and Cmd+[/]
  are handled at the CEF keyboard layer so they still work with renderer
  focus; key actions are gated to raw key-down events to prevent duplicate
  tab creation. The browser-client tab anchor is also repaired when the
  active/first tab closes, so a later popup/Cmd+T still joins the surviving
  native tab group.
- **Native Chromium sandbox.** macOS Helper now initializes
  `CefScopedSandboxContext` before dynamically loading CEF. Helpers resolve
  one shared framework copy from the parent bundle; duplicate framework
  loading is removed. Native CEF sandbox is default. Set
  `LETHE_CEF_NATIVE_SANDBOX=0` for legacy Lethe Seatbelt mode.
- **Download + permission boundaries.** Downloads are constrained to
  `~/Downloads`, filenames are sanitized, each transfer is capped at
  512 MiB, and privileged permission prompts fail closed until explicit UI
  approval exists.
- **Proxy auth + CONNECT works.** `GetAuthCredentials`
  is wired to answer the policy proxy's 407 with the per-launch token
  (only ever to 127.0.0.1 on our own port). The browser-info startup fix
  keeps the renderer handshake alive long enough for authenticated CONNECT.
  Repeated cold CEF launches complete external HTTPS page loads.
- **Sandbox.** The shared Seatbelt profile honors
  `LETHE_SANDBOX_EXTRA_WRITE_DIRS` for the CEF user-data dir.

## Current limitations

Real HTTPS page loads work through policy-proxy authentication. Blink boots,
native Chromium sandboxing works, and the shared basic e2e checklist now
passes on cold launches.

1. **Browser-info handshake remains a regression risk.** CEF's renderer
   browser-info acknowledgement can be delayed on cold macOS launches.
   Current build disables the default timeout so slow-but-valid startup is not
   converted into dropped navigation. The latest three pageload runs completed
   all 8/8 sites with zero timeouts; a fresh startup+pageload run also completed
   8/8 with zero timeouts.
2. **Outer Seatbelt + native CEF sandbox cannot be combined.** macOS does
   not support nested sandbox initialization. Blink therefore defaults to
   Chromium's dedicated sandbox; Lethe's older Seatbelt remains explicit.

3. **E2E screenshots use the Blink DevTools capture path.** macOS CoreGraphics
   snapshots of CEF Alloy accelerated surfaces can capture the desktop or an
   incomplete AppKit host instead of the renderer surface. `screenshot` now
   calls `Page.captureScreenshot` and writes the returned PNG, which keeps the
   artifact deterministic and renderer-backed.

4. **Renderer eval is navigation-tolerant.** JS-heavy pages can perform a
   post-load renderer navigation after `wait` (YouTube does this in the
   current CEF build). `assert-js` therefore polls with short eval timeouts
   instead of holding one renderer-context request for the full five-second
   timeout.

## E2E and benchmark verification

- **G2 basic e2e:** `tests/e2e/basic.lethe` completed with exit code 0.
  This covers HTTPS navigation, link navigation, history, address-bar search,
  CEF tabs plus native AppKit tab-group creation/removal, YouTube DOM/JS execution, private-network blocking, `.invalid`
  special-use blocking, reader-command compatibility, and `target=_blank` tabs.
  The latest run also completed final browser teardown, reached `CefShutdown`,
  shut down the shared engine, and exited 0 with no new `lethe-cef*.ips` report.
- **H1 benchmark:** `tools/bench/bench.mjs` accepts `--browser lethe-cef` and
  dispatches it through the same benchmark path as the other Lethe variants.
  Latest `startup,pageload` run: startup 249 ms, 8/8 page loads, 0 timeouts,
  exit 0.
- **Proxy concurrency:** automatic policy-proxy worker capacity is now bounded
  at 8-16 workers instead of 4-8, preventing media-heavy Blink pages from
  occupying every worker and starving the next top-level navigation.

Ruled out (round 3): missing renderer resources (ICU / V8 snapshot /
paks all present in every bundle), crash of the renderer (no .ips, and
ps never shows a renderer at all when the bundle is missing), invalid
bundle identifiers, embedded proxy credentials (Chromium strips
user:pass from --proxy-server; see net/docs/proxy.md), and
Proxy-Authorization passed as a custom X- header (Chromium strips
Proxy-Authorization from CONNECT extra headers; custom X- headers were
not verified to survive the tunnel either).

## Next steps (for a later round)

1. Compare against pristine cefclient behind the same policy proxy if
   browser-info handshake regressions return.
2. Replace the HTTP loopback proxy capability mechanism with a
   Chromium-compatible authenticated transport, or move policy proxy into
   a separately privileged process with OS-level IPC capability.

## Driver notes

- `CefBrowserProcessHandler` used to be null (never instantiated);
  `OnBeforeChildProcessLaunch` / `OnContextInitialized` now work.
- The e2e driver uses native `CefFrame::LoadURL` after the initial browser
  frame is ready. This preserves browser-process navigation semantics for
  downloads and media while the driver tracks pending navigation until the
  corresponding load events arrive.
- `--single-process` loads pages (useful as a navigation sanity check)
  but is not a supported shipping mode.
