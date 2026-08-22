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
- Aletheia OS bridge: `openUrl`/`navigate`/`goBack`/`goForward`, VPN control,
  LLM web search + page reading, status reporting

### Security
- Strict CSP decision semantics (`'self'` origin+path-boundary matching,
  fail-closed on originless documents, script-scheme denial)
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

### Quality & infrastructure
- 114-test suite (lightweight framework, no external test deps) including
  full-stack navigation e2e against real local origins and TLS origins with
  CA-bundle trust
- CI: Linux (gcc/clang, incl. a GTK3 GUI job) + macOS build/test/e2e matrix
  and an ASan+UBSan sanitizer job
- Hardenened builds by default (`-fstack-protector-strong`, `-Wall -Wextra`,
  LTO, `_FORTIFY_SOURCE=2`)
- Async-signal-safe termination handling in the engine

[1.0.0]: https://github.com/hotocoo/lethe
