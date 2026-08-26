# Changelog

All notable changes to Lethe are documented in this file.

## [1.0.0] — 2025

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
- 181-test suite (lightweight framework, no external test deps) including
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

[1.0.0]: https://github.com/hotocoo/lethe
