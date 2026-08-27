# Lethe vs. the browsers: an honest security & performance comparison

*Written by the Lethe team, held to a no-marketing standard. Every claim
about Lethe below is backed by code in this repository or a measurement
reproduced with tools/fetch_bench or ps. Where we are weaker than the
incumbents, we say so plainly.*

## What Lethe actually is (v0.2.0)

A privacy-hardened **network stack** wrapped in a native browser shell:

- The platform web engine renders pages (WKWebView on macOS, WebKitGTK on
  Linux, WebView2/Chromium on Windows) - JavaScript, CSS, media, YouTube
- Lethe's shell supplies the chrome (tabs, address bar, history, find,
  downloads, dialogs) and gates EVERY navigation through its policy layer;
  on macOS 14+ and Linux all engine traffic also rides Lethe's local policy
  proxy so subresources are enforced at the transport layer
- Reader view re-fetches the page through Lethe's own stack (TLS 1.3 floor,
  pinning, HSTS, partitioned cookies) and renders extracted text with a
  script-free CSP
- Built-in third-party tracker protection (227 curated hosts, content-blocker
  rules inside the engine; Windows via WebResourceRequested)
- HTTPS-first for top-level navigations; Oblivion windows are https-only
- Oblivion windows: isolated in-memory store wiped on close, tracker
  protection forced, stealth UA, no plaintext - Lethe's private mode
- WireGuard-style built-in VPN with fail-closed routing
- DoH-only DNS, HSTS pre-connect upgrade, SPKI certificate pinning,
  private-network (SSRF) isolation, RFC6265bis partitioned cookies,
  enforced Seatbelt/seccomp sandboxing of the app itself

## Architecture matrix

| | Engine | JS engine | Renderer sandbox | Site isolation | Network privacy |
|---|---|---|---|---|---|
| **Chrome/Edge** | Blink | V8 | Multi-layer broker/render/GPU, heap cages | Yes, per-site processes | Optional DoH |
| **Firefox** | Gecko | SpiderMonkey | Content processes + RLBox parsers | Fission rolling out | DoH optional |
| **Safari** | WebKit | JavaScriptCore | WebContent/GPU/Net services + seats | Per-tab isolation | ITP |
| **Brave** | Blink | V8 | Inherits Chromium | Inherits Chromium | Shields, Farbling, Tor windows |
| **Tor Browser** | Gecko ESR fork | SpiderMonkey, JIT-restricted | Firefox sandbox + circuit isolation | First-party per circuit | All traffic via circuits; no local DNS leak |
| **Lethe (reader)** | Own text extractor | **None** | **None: single process** WARN | n/a | DoH-only, HSTS upgrade, pins, SSRF guard, tunnel-or-refuse |
| **Lethe (full-web)** | Platform engine | JSC / JSC / V8 | **Inherited from platform engine** | Inherited | Nav gate everywhere + transport proxy (macOS 14+, Linux); Windows nav gate only; CONNECT bypasses pinning/HSTS-inspection WARN |

## Security: where Lethe genuinely wins

1. **No plaintext DNS, ever, for targets.** DoH failure blocks instead of
   leaking (fail closed). Chrome/Firefox/Safari treat DoH as opportunistic.
2. **Private-network (SSRF) isolation on every hop.** Resolved addresses
   are scope-classified before any socket; numeric spell-outs like
   http://2130706433/ are canonicalized so they cannot dodge the check.
   No mainstream consumer browser ships this as default-on fetch policy.
3. **Tunnel-or-refuse routing.** A destination covered by VPN CIDRs is
   never dialed plaintext while the tunnel is down - kept-alive sockets
   included (tested). Consumer VPN browsers do not make this guarantee.
4. **Certificate pinning additive to verification**, enforced on every
   handshake including redirect hops and TLS-over-tunnel.
5. **Smaller parser surface in reader mode**: no JS, no CSSOM, no image
   decoders, no media pipelines. The classic web exploit chain (JIT type
   confusion -> renderer escape) has no foothold because there is no JS.
6. **Enforced OS sandbox on the app itself** (Seatbelt profile / seccomp
   allowlist) - the test suite itself runs under it.
7. **The local policy proxy is not an open proxy.** It demands a per-launch
   token (407 otherwise) so no other local process can ride the VPN tunnel
   or the policy identity. Chrome/Firefox have no equivalent component; a
   naive "route the engine through a local proxy" design (0.1.0 included)
   hands every local process a free tunnel.
8. **Tracker protection on by default, in the engine.** Chrome ships none;
   Safari/Firefox ship ITP/ETP (smarter, larger). Lethe's list is small and
   hand-curated - and measured: see docs/BENCHMARKS.md for bytes and
   requests removed per page.
9. **Oblivion windows are strictly stronger than Incognito.** Incognito
   forgets; Oblivion also refuses plaintext, forces the blocker on and
   presents a fixed UA. Incognito still lets sites fingerprint the real UA
   and load http://.

## Security: where Lethe loses - read this part

1. **Single-process reader renderer.** The HTML-to-text extractor parses
   hostile bytes inside the main process with no renderer sandbox. Any
   memory-safety bug there is directly exploitable in-process. Chromium
   spent a decade making exactly this bug class non-fatal; we have not.
2. **Full-web mode inherits the platform engine's CVE exposure wholesale.**
   Opening YouTube there carries the same risk as Safari/GNOME Web/Edge.
   We add policy, not invulnerability.
3. **CONNECT tunnels are opaque by design.** The proxy sees only
   host:port - certificate pinning and HSTS inspection do NOT apply inside
   (the engine's own verifier still runs). Documented, not hidden.
4. **Windows host enforces at navigation granularity only** (scheme +
   resolved-address scope checks). Linux-style subresource transport
   enforcement does not exist there yet.
5. **Stealth UA is a fingerprinting liability.** One fixed rare string is
   MORE identifying than Chrome's ocean. Tor solves this with uniformity;
   a niche browser cannot. Stealth mode is a blunt tool, not anonymity.
6. **The built-in VPN is not Tor.** WireGuard-style tunnels move trust to
   OUR endpoint, which sees your IP and destinations. No circuits, no
   per-tab isolation, no defense against a global passive adversary. If
   you need anonymity, use Tor Browser. Full stop.
7. **Cookie jar is memory-only** - privacy win, UX loss (logins vanish).
8. **No site isolation, no fuzzing program, no audits.** Chrome and Tor
   run continuous fuzzing and paid bounties; Lethe has a 234-test suite,
   CI sanitizers and an honest README. That is not comparable assurance.
9. **CVE-scale reality** (approximate public-tracker orders of magnitude):
   Chromium thousands of fixed vulns lifetime; Gecko/WebKit hundreds to
   thousands each; Tor inherits Gecko's. Lethe has near-zero reported CVEs
   because approximately nobody has audited it. Low count != assurance.

## Performance: measured, not vibes

**As of 0.2.0 the authoritative numbers live in docs/BENCHMARKS.md**,
produced by `tools/bench` running Lethe and Chrome through identical steps
on the same machine (page loads, RSS, CPU, YouTube playback, Speedometer,
JetStream, MotionMark). The figures below are the older 0.1.0 probes.

Loopback HTTP through the real client stack (keep-alive, policy pipeline
active; tools/fetch_bench --self, Apple Silicon, Release):

```
requests=3000  ok=3000  keepalive_ops_per_s=39830.7  mean_ms=0.025
requests=10000 ok=10000 keepalive_ops_per_s=54249.9  mean_ms=0.018
```

Initial resident footprint after first paint (same machine, launch ->
settle -> sum RSS of process tree):

| Browser | Initial RSS |
|---|---|
| **Lethe (reader mode)** | **~86 MB** |
| Safari (start page) | ~450 MB |
| Chrome (about:blank) | ~2.3 GB across 24 processes |

Reader-mode page loads through mock-DoH origins complete in single-digit
milliseconds end-to-end in the e2e suite (see tests/).

**Where these numbers must not be abused:**

- Speedometer/JetStream measure JS engines. Reader mode has none - those
  benchmarks are meaningless for it. Full-web mode uses the platform
  engine, so its scores ARE Safari's/GNOME Web's/Edge's scores on that
  machine; we claim no delta.
- Loopback ops/s says nothing about real-world page-load latency, which
  is dominated by network RTT and, in full-web mode, the platform engine.
- Chrome's memory is the price of site isolation + JIT + GPU processes -
  features reader-mode Lethe simply lacks.

## Verdict

- Maximum web compatibility with strong isolation engineering:
  **Chrome/Edge or Firefox**.
- Anonymity against network observers and fingerprinting: **Tor Browser**
  - nothing here competes with it, including our VPN.
- Apple-integrated privacy: **Safari**; polished ad/track blocking:
  **Brave**.
- Minimal attack-surface reading surface, guaranteed-no-plaintext-DNS
  fetching, fail-closed VPN routing, LLM-agent-grade page access:
  **Lethe** - accepting that its renderer hardening, audit depth and web
  compatibility are years behind the incumbents, and that full-web mode
  deliberately trades some minimalism back for compatibility.
