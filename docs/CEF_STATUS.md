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
- **Proxy auth plumbing.** `GetAuthCredentials` answers the policy
  proxy's 407 with the per-launch token (only ever to 127.0.0.1 on our
  own port), `disable-chrome-login-prompt` routes login challenges to
  the embedder instead of Chrome's nonexistent login UI, and
  `OnBeforeResourceLoad` stamps a pre-emptive Proxy-Authorization on
  every request (Chromium uses a request-level header directly on the
  CONNECT tunnel). With the flow engaged, the tunnel reaches
  `200 Connection Established` and the TLS handshake through it
  completes with the real server certificates.
- **Sandbox.** The shared Seatbelt profile honors
  `LETHE_SANDBOX_EXTRA_WRITE_DIRS` for the CEF user-data dir.

## What is still broken (round-3 findings)

Real https page loads are unreliable; about:blank and the in-process
paths work. Two intermittent failure points, both inside CEF/Chromium
plumbing rather than Lethe's stack:

1. **CEF frame handshake is flaky.** CEF's renderer normally answers
   the browser's "new browser info" request per frame; in this build
   the reply intermittently never arrives (`Timeout of new browser
   info response for frame ... (has_rfh=1)`). While a frame has no
   browser info, `CefFrame::LoadURL` is silently dropped and the proxy
   auth challenge is not routed to `GetAuthCredentials` (no frame to
   route through), so the CONNECT is 407'd in a loop and the
   navigation hangs or dies with ERR_INVALID_AUTH_CREDENTIALS. In runs
   where the handshake completes, the same navigation gets through the
   tunnel with the pre-emptive credentials.
2. **Cert verify can hang under the inherited Seatbelt.** With the
   tunnel established, the network service's cert-verifier job
   sometimes waits with no network activity until the 30 s connect-job
   timeout (net_error -7). Removing `disable-component-update` (the
   builtin verifier waits for Chrome root-store data that pipeline
   delivers) did not fully eliminate it. Suspected: the browser
   process's Seatbelt profile is inherited by every helper and
   something in the macOS trustd / root-store path needs a write or
   XPC the profile gates. Running with `--disable-sandbox` changes the
   failure mode (fast 407 instead of a hang), which keeps the sandbox
   in the suspect list.

Ruled out (round 3): missing renderer resources (ICU / V8 snapshot /
paks all present in every bundle), crash of the renderer (no .ips, and
ps never shows a renderer at all when the bundle is missing), invalid
bundle identifiers, embedded proxy credentials (Chromium strips
user:pass from --proxy-server; see net/docs/proxy.md), and
Proxy-Authorization passed as a custom X- header (Chromium strips
Proxy-Authorization from CONNECT extra headers; custom X- headers were
not verified to survive the tunnel either).

## Next steps (for a later round)

1. Compare against the pristine cefclient binary from the same CEF
   dist behind the same policy proxy: if cefclient also 407-loops, the
   frame-handshake flake is upstream and worth a CEF issue; if it
   loads, diff the app/bootstrap settings against ours.
2. Instrument the Seatbelt theory for the cert-verify hang: run the
   sandboxed shell with `sandbox_compile_file`-style deny logging
   (`LETHE_DEBUG=1` + `log stream --predicate 'sender == "Sandbox"'`)
   during a hang, and/or temporarily allow `~/Library/Keychains`
   writes.
3. Consider bumping CEF (the dist is 151.3.24+chromium-151.0.7922.174);
   the frame-handshake code moved upstream more than once.
4. Once real pages load: re-run the e2e suite (G2) and add lethe-cef
   as a third browser in tools/bench (H1).

## Driver notes

- `CefBrowserProcessHandler` used to be null (never instantiated);
  `OnBeforeChildProcessLaunch` / `OnContextInitialized` now work.
- The e2e driver navigates via the renderer
  (`ExecuteJavaScript location.assign`) because `CefFrame::LoadURL` is
  dropped while the frame handshake is in flight; the driver waits for
  the first main-frame commit before the first load.
- `--single-process` loads pages (useful as a navigation sanity check)
  but is not a supported shipping mode.
