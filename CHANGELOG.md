# Changelog

All notable changes to Lethe are documented in this file.

## [0.1.0] — 2026-08-27

First version that is a usable browser. Earlier tags "1.0.0"/"1.1.0" were
mislabelled: the GUI was a blank window whose widgets were never attached,
and the TLS context had no trust anchors, so no HTTPS (or DoH) connection
could succeed. Their content is folded in below under the honest number.

### Browser shells
- macOS: native AppKit shell around WKWebView (`src/ui/mac/`). Tabs are
  native NSWindow tabs (⌘T/⌘W/⌃⇥, drag to reorder, merge/move); address bar
  with search fallback; back/forward/reload/stop; load progress; https lock
  indicator; find bar (⌘F); zoom; print; downloads to `~/Downloads`;
  JavaScript alert/confirm/prompt; file-upload panel; HTTP Basic/Digest
  prompt; `window.open`/`target=_blank` open beside the current tab; reader
  view (⌘⇧R); block/error/new-tab internal pages; Security Status panel;
  VPN toggle and Clear Browsing Data in a Privacy menu. Bundle Info.plist
  registers http/https so Lethe can be the default browser. No GTK on macOS
  (DMG shrank from 12.7 MB to 2.9 MB).
- Linux: the GTK3 shell is now a browser: WebKitGTK view per tab in a
  notebook, header-bar navigation, address entry with progress, find
  revealer, zoom, reader view, downloads, keyboard shortcuts (Ctrl+T/W/L/R/F,
  Alt+←/→, F5, F11, Ctrl+1..9). Reader-only Cairo fallback when WebKitGTK is
  absent. Dead widgets (`tab_bar`, `address_bar`, `fullweb_*`) removed.
- Every WebKit navigation is gated off the main thread by
  `HttpClient::policyCheckUrl` (DoH-only, private-network guard on the
  RESOLVED address, VPN fail-closed). On macOS 14+ (`proxyConfigurations`)
  and on Linux (`WEBKIT_NETWORK_PROXY_MODE_CUSTOM`) all engine traffic rides
  the local PolicyProxyServer so subresources are enforced at transport.
- Shared across shells: `browser/url_input` (address text -> URL: explicit
  http(s) kept, bare hosts get https:// / loopback http://, everything else
  including `javascript:`/`data:`/`file:` becomes a search) and
  `renderer/page_templates` (script-free internal pages with CSP meta).
- `--e2e-script <file>`: scripted driver with the same command language on
  macOS and Linux (docs/E2E.md); `tests/e2e/basic.lethe` is the release
  checklist and passes on both.
- `--persistent` keeps site data; default stays ephemeral. `--no-proxy`,
  `--version`, `--help`.

### Security fixes
- TLS: `SSL_CTX_set_default_verify_paths` was never called, so a context
  without an explicit CA bundle had NO trust anchors and every verified
  handshake failed ("SSL error 1"). Fixed; failures now print the
  certificate verify result / OpenSSL error text.
- TLS: hostname verification (`SSL_set1_host`, IP SANs for literals) added on
  the direct and relay paths - previously any valid certificate for any
  host was accepted.
- Reader extraction: numeric character references are emitted as UTF-8 (raw
  0x80-0xFF bytes previously corrupted documents); nav/header/footer/aside/
  noscript/template/svg/iframe regions dropped from reader text.
- macOS Seatbelt profile additionally allows writes to `~/Downloads` and
  Lethe's own `~/Library` subtrees (persistent WebKit profile, window state).
- Linux GUI: the multi-process WebKit engine cannot run under the engine's
  default-deny seccomp filter (children inherit it); the shell relies on
  WebKitGTK's bubblewrap + seccomp content sandbox instead and says so in
  the Security Status panel. The engine filter still guards the reader-only
  build and the test suite.

### Build / CI / release
- Version single-sourced from `project(lethe VERSION 0.1.0)`; `config.h`
  reads `LETHE_VERSION`.
- macOS: `browser/app/Info.plist.in`, ARC, Cocoa/WebKit/Network frameworks;
  release workflow no longer installs GTK on macOS.
- `Dockerfile.linux-build`: Ubuntu 24.04 image that builds the GTK shell,
  runs the unit tests and the headless e2e under Xvfb.
- 221 unit tests (url input, page templates, UTF-8 entities, boilerplate
  regions added).

### Previously labelled "1.1.0" (2026-08-26, retracted label)

### Full-web mode: platform engines behind Lethe policy
- Local PolicyProxyServer: HTTP forwarding + CONNECT splicing where every
  dial runs DoH-only resolution, private-network scope checks and VPN
  fail-closed routing; CONNECT is raw so engines keep end-to-end TLS
- macOS: WKWebView embedding with navigation gating and raster-scale
  control (FSR-style downscale AND DLAA-style supersampling up to 2.0x)
- Linux: WebKitGTK wired to the local proxy for subresource-level
  transport enforcement
- Windows: WebView2 host executable (.exe) with navigation policy gate,
  resolved-address scope classification and native RasterizationScale
- docs/COMPARISON.md: honest cross-browser security/performance audit
  (Chrome/Firefox/Safari/Edge/Brave/Tor), including Lethe's weaknesses
- 5 new proxy security tests incl. verified TLS 1.3 splice; suite at 210

### Previously labelled "1.0.0" (2026-08-26, retracted label)

### Browser engine & OS integration
- Single-process browser engine with tab management, per-tab navigation
  history (1000-entry cap), and incognito-by-default sessions that never
  record history
- Real page loads through the secure stack (DoH resolution + VPN fail-closed
  policy) with title extraction, per-tab reader-text caching, redirect-aware
  final-URL bookkeeping, and session back/forward traversal that fails closed
- Reader-mode HTML rendering in the viewport (titles, headings, lists,
  entities)
- Focus mode (Ctrl+Shift+F hides the address entry and menu button) and a
  tab strip that stays hidden while a single tab is open
- Aletheia OS bridge: `openUrl`/`navigate`/`goBack`/`goForward`, VPN control,
  LLM web search + page reading, status reporting

### Security
- Certificate pinning: per-host SPKI SHA-256 pins ("sha256-<base64>") that
  narrow what a VERIFIED chain may contain - leaf, intermediate, or root may
  satisfy; enforced on every TLS handshake (direct and TLS-over-tunnel alike,
  redirect hops included) right after ordinary verification, failing closed
  before any request bytes leave; configured via Config.certPins or
  LETHE_CERT_PINS, malformed entries rejected loudly instead of silently
  weakening a host's constraint
- Private-network isolation (SSRF guard): every hop's RESOLVED destination
  is scope-classified before any socket or tunnel exchange; non-loopback
  private scopes (RFC1918, CGNAT, link-local/cloud-metadata, IPv6 ULA,
  NAT64/6to4/IPv4-mapped embedded IPv4, TEST-NET/benchmarking/multicast/
  reserved) fail closed with named reasons; numeric IPv4 spell-outs are
  canonicalized through the dialing resolver (glibc octal vs Apple decimal
  leading-zero semantics both honored); loopback stays reachable and
  LETHE_PRIVATE_NET_MODE / LETHE_PRIVATE_NET_ALLOW configure the escape
  hatches
- Strict CSP decision semantics (`'self'` origin+path-boundary matching,
  fail-closed on originless documents, script-scheme denial)
- HSTS enforcement (RFC 6797): in-memory policy cache fed by
  Strict-Transport-Security headers on verified https:// hops only; every
  later http:// request to a covered host is rewritten to https:// before
  any network I/O — plaintext is never attempted and there is no insecure
  fallback; max-age=0 revokes, includeSubDomains covers subdomains,
  IP literals never carry policy, memory-bounded and purged at shutdown
- SameSite cookie semantics (RFC6265bis): Lax-by-default delivery with
  the top-level-navigation/safe-method allowance; SameSite=None honored
  only with Secure (rejected outright otherwise); __Secure-/__Host-
  name-prefix enforcement at storage time, matched case-insensitively,
  with __Host- requiring a host-only cookie from an https origin carrying
  an explicit Path=/; a rejected Set-Cookie neither plants nor deletes
  state. HttpClient hands every hop (redirect hops included) its real
  initiator URL, navigation kind, and RFC7231 method safety to the jar,
  so cross-site subresource/API traffic never carries Lax or Strict
  cookies while genuine link-click navigations still work
- Navigation request hygiene: Referer is COMPUTED per hop under the
  Referrer-Policy engine (strict-origin-when-cross-origin default:
  full URL same-origin, origin-only cross-origin, nothing survives an
  https->http downgrade); a response's Referrer-Policy header governs
  later hops of its request chain (last known token wins, unknown
  lists ignored); top-level navigations send Sec-Fetch metadata and
  Upgrade-Insecure-Requests while API fetches stay wire-compatible;
  a fail-closed allowlist refuses every non-http(s) scheme - including
  redirect targets - before any network I/O
- Enforced sandboxing: macOS Seatbelt profile and Linux seccomp-bpf
  default-deny allowlist with `PR_SET_NO_NEW_PRIVS`
- TLS 1.3-only policy with certificate verification always on; optional
  engine-provided CA bundle for private PKIs (`Config.caBundlePath`)
- DNS-over-HTTPS resolution (Cloudflare by default) — plaintext DNS is never
  used for targets; DoH failure blocks rather than leaks

### Built-in VPN
- WireGuard-style cryptography: X25519 handshake, ChaCha20-Poly1305 AEAD,
  HMAC-SHA256 indexed mac1/key rotation semantics, HKDF-SHA256 derivation
- Anti-replay (64-bit counter, 2048-packet sliding window), REJECT_AFTER_TIME
  session expiry, transparent rekey at 2/3 lifetime, NAT keepalives,
  exponential-backoff handshake retries
- Fail-closed CIDR routing: covered destinations are never fetched in
  plaintext while the tunnel is down; no plaintext fallback when relaying is
  disabled server-side
- HTTP/HTTPS streaming relay over the tunnel (OPEN/DATA/END framing with
  exchange ids); TLS runs inside the encrypted stream via memory-BIO
  handshake; key material zeroized on teardown/disable
- Portable UDP transport (IPv4/IPv6, timeouts) and a standalone reference
  server with authenticate-first dispatch, per-source handshake rate limiting,
  concurrent-client caps, and idle eviction
- Standalone e2e client binary plus `scripts/e2e_vpn_loopback.sh` deployment
  sim used locally and in CI

### Live network stack
- `HttpClient`: real TCP (IPv4/IPv6), OpenSSL TLS 1.3, HTTP/1.1 with
  keep-alive, chunked/content-length/read-until-close bodies, gzip/deflate,
  redirect following
- LLM search service: structured results, readable text extraction over real
  HTTP(S), VPN-routed by default
- Partitioned cookie jar: per-top-level-site isolation in memory only,
  host-only/Domain/path/Secure/HttpOnly scoping, Max-Age and Expires expiry,
  capacity-bounded; Set-Cookie captured on every redirect hop and Cookie
  attached by partition through HttpClient (explicit caller headers win);
  Engine purges everything on shutdown — nothing persists to disk
- Runtime environment configuration: LETHE_SANDBOX, LETHE_DNS_PROVIDER and
  LETHE_USER_AGENT_MODE are honored at startup; command-line flags win;
  standard UA now reports the honest platform while stealth mode pins one
  fixed low-entropy profile

### Performance (Aletheia workload optimizations)
- HTTP/1.1 keep-alive connection reuse: repeat fetches to the same origin
  ride ONE connection instead of paying TCP+TLS setup per request; the
  server's Connection: close is honored; a stale idle connection is retried
  transparently exactly once; redirect hops stay on one connection
- VPN fail-closed policy is re-evaluated on EVERY reused connection: a
  kept-alive socket can never become a plaintext path around a dropped
  tunnel
- DNS-over-HTTPS answer cache: repeat hostnames resolve once within a TTL
  (300s default, configurable, 0 disables); only successful answers are
  cached and provider changes invalidate it - fail-closed semantics
  unchanged
- Buffered response parsing: header lines and chunked framing no longer
  cost a select()+recv() syscall pair per byte on plain TCP; buffered bytes
  survive across keep-alive responses
- LLM agent caches: successful page reads and identical search queries are
  memoized with TTL + LRU bounds (config via SearchConfig), so agent
  re-reads avoid the network entirely; browser navigation uses readPageFresh
  and keeps fetching every document for real through the secure stack
- Search result quality: entity-decoded titles, snippets extracted from
  result blocks, empty/same-engine anchors filtered as noise, duplicate
  URLs collapsed; caller-supplied headers (User-Agent etc.) now reach the
  server instead of being shadowed by client defaults

### Quality & infrastructure
- 205-test suite (lightweight framework, no external test deps) including
  full-stack navigation e2e against real local origins and TLS origins with
  CA-bundle trust
- CI: Linux (gcc/clang, incl. a GTK3 GUI job) + macOS build/test/e2e matrix
  and an ASan+UBSan sanitizer job
- Hardenened builds by default (`-fstack-protector-strong`, `-Wall -Wextra`,
  LTO, `_FORTIFY_SOURCE=2`)
- Async-signal-safe termination handling in the engine
- GTK3 UI layer repaired: signal handlers use valid C-callback patterns,
  the address bar no longer returns dangling references, and the GUI
  target compiles and links cleanly (pkg-config imported target, so
  non-system GTK installs work too)

[0.1.0]: https://github.com/hotocoo/lethe
