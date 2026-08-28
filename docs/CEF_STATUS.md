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
  runs. (Previously this aborted in `chrome_main_delegate.cc` /
  `path_service.cc`.)
- **Shared bootstrap.** `ShellBootstrap` is shared: same engine
  init, same policy proxy, same DoH pool, same per-launch auth token.
  The CEF net stack is pointed at the local policy proxy via
  `OnBeforeCommandLineProcessing` (proxy-server + proxy-auth).
- **Sandbox fix.** The shared macOS Seatbelt profile now honors
  `LETHE_SANDBOX_EXTRA_WRITE_DIRS` (colon-separated). The CEF shell
  sets it to its user-data dir so Chromium can write its
  SingletonLock and per-profile caches. Without this, the Seatbelt
  profile denied the SingletonLock write and CefInitialize aborted.
- **Render handler in the Helper.** The CEF Helper binary now links
  `cef_render_handler.mm` and registers a
  `LetheCefRenderHandler` via `GetRenderProcessHandler`, so the
  renderer can answer the browser's `lethe:eval` process messages
  (the e2e / bench eval path).

## What is still broken

- **The renderer subprocess does not launch.** CEF spawns the GPU,
  network, and storage Helper processes, but never a
  `--type=renderer` process. Every navigation (even
  `about:blank` and `data:` URLs) is reported as
  `ERR_ABORTED (-3)`, and the `lethe:eval` round-trip times out
  (no renderer to reply). This blocks:
  - **G2** (`lethe-cef --e2e-script ...` loading example.com)
  - **H1** (a bench run that includes `lethe-cef` as a third browser)

### Round 2 investigation findings

- **Not a crash.** No renderer crash reports are generated. The
  renderer process simply never appears in the process list (verified
  by continuous monitoring over 10 s).
- **Not a network issue.** `data:text/html` URLs also abort with
  `ERR_ABORTED`, so it is not the policy proxy or DNS.
- **Not a missing resource.** The ICU data (`icudtl.dat`) and the
  CEF framework are present in both the main bundle and the Helper
  bundle. The GPU / network / storage Helpers launch fine using the
  same Helper binary and framework.
- **CEF verbose logging is silent.** `--enable-logging=stderr --v=2`
  produces no renderer-launch lines, suggesting the browser process
  is not even attempting to launch a renderer (or the attempt is
  failing before logging).
- **Hypothesis.** The navigation is being aborted before the
  RenderFrameHost requests a renderer. Possible causes to investigate:
  1. A race in `CreateBrowserSync` where the initial navigation is
     cancelled before the renderer is attached.
  2. A CEF/Chromium process-launch configuration issue (e.g., a
     missing switch or an incorrect subprocess path for the renderer
     specifically).
  3. A conflict between Lethe's Seatbelt sandbox and the renderer
     launch (less likely, since other Helpers launch fine).

## Next steps (for a later round)

1. Inspect the CEF process-launch path: confirm the browser process
   is actually calling the renderer launcher and with what args.
2. Check whether the missing renderer is due to a CEF setting
   (`no_sandbox`, subprocess path, or a missing switch) versus a
   Chromium content-layer issue.
3. Once the renderer launches, re-verify the `lethe:eval` round-trip
   and run the e2e + bench suites.
