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
  `about:blank`) is reported as `ERR_ABORTED (-3)`, and the
  `lethe:eval` round-trip times out (no renderer to reply). The CEF
  log shows no renderer-launch attempt or error, which points at a
  CEF/Chromium process-launch configuration issue rather than a
  Lethe bug. This blocks:
  - **G2** (`lethe-cef --e2e-script ...` loading example.com)
  - **H1** (a bench run that includes `lethe-cef` as a third browser)

## Next steps (for a later round)

1. Inspect the CEF process-launch path: confirm the browser process
   is actually calling the renderer launcher and with what args.
2. Check whether the missing renderer is due to a CEF setting
   (`no_sandbox`, subprocess path, or a missing switch) versus a
   Chromium content-layer issue.
3. Once the renderer launches, re-verify the `lethe:eval` round-trip
   and run the e2e + bench suites.
