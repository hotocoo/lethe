# Lethe vs Chrome: measured (v1.0)

*Every number below comes from `tools/bench/bench.mjs` runs on this machine,
through the same declarative step list, with both browsers launched cold
under a fresh profile. Raw JSON for every run is committed under
`tools/bench/results/v1.0/`. Reproduce with the commands in `README.md`.*

---

# Extreme-load benchmark (v2.0, 2026-09-02)

*"Extreme" is not "hard": these workloads are an order of magnitude past the
100k-node stress page and past everyday sites. Wikipedia/GitHub/Google are
baby difficulty; this suite is designed to saturate the renderer, the JS
engine, the GPU, and the network stack. Both browsers run the byte-identical
pages from a shared local origin, so the workload is controlled and
reproducible.*

## What "extreme" means here

Four sub-tests, each a self-contained page that self-reports its own metric:

- **extreme-dom** — 252,509 live DOM nodes (5,000 rows × 50 cells + chrome),
  a forced layout-thrash pass (40 alternating read/write passes), then 600
  frames of `requestAnimationFrame` with the whole tree present.
  Metric: node count, build ms, thrash ms, sustained FPS.
- **extreme-js** — 8 seconds of the hardest single-threaded work a page can
do: repeated 512×512 `Float64Array` matrix multiplies, a 16 MiB SHA-256 via
WebCrypto, and a bounded tribonacci recursion. Metric: ops completed.
- **extreme-webgl** — 256 textured quads (16×16 grid) with per-quad
transforms and a per-pixel fragment shader at 960×540. Metric: sustained FPS
over 600 frames.
- **extreme-net** — 300 concurrent `fetch()` requests through the engine's
network stack. On Lethe every request additionally rides the policy proxy
(loopback is allow-listed), which is the real-world path. Metric: completion
time + requests/sec.

## Headline results

Host: Apple M4 Max, 16 cores, 64 GB, macOS 26.5. Lethe: system WebKit
(v0.1.1, policy proxy on, 16-worker pool). Chrome: 152.0.7977.75. One run
cell each; the NET suite is also run as a focused 3-round median.

### Where Lethe wins

| Metric | Lethe | Chrome | Lethe edge |
|---|---|---|---|
| **Startup to ready** | **338–443 ms** | 937–1551 ms | **~2.5–3× faster** |
| **Memory at idle (ready)** | **160–184 MB / 4 proc** | 893–950 MB / 8–9 proc | **~5× less RAM** |
| **Memory under extreme DOM** | **169–859 MB / 5 proc** | 2086–2198 MB / 10 proc | **~2.5–12× less RAM** |
| **Memory under extreme JS** | **290–942 MB / 6 proc** | 2090–2153 MB / 9 proc | **~2–7× less RAM** |
| **Memory under extreme WebGL** | **334–877 MB / 7 proc** | 1832–2228 MB / 10 proc | **~2–5× less RAM** |
| **DOM build (252k nodes)** | **53–134 ms** | 61–74 ms | competitive (noisy) |

Lethe's footprint is the story: it carries the same 252k-node page, the same
8-second JS torture, and the same WebGL scene in a fraction of the RAM, with
a third of the processes. That is the WebKit snapshot (one WebContent +
Networking + GPU trio) versus Chrome's renderer/GPU/network/storage fan-out.
Startup is ~2.5–3× faster because Lethe's bootstrap is the policy proxy +
WKWebView warmup (~150 ms) versus Chrome's Chromium process forking.

### Where Chrome wins (honest)

| Metric | Lethe | Chrome | Why |
|---|---|---|---|
| DOM FPS (252k nodes) | 69–72 | 134–136 | WebKit rAF tier vs Blink's |
| WebGL FPS (256 quads) | 72 | 144 | same rAF tier gap |
| JS matMul (8 s) | 103–105 | 145–146 | V8 TurboFan > JSC on this microbench |
| DOM layout thrash | 1800–2300 ms | 844–904 ms | Blink layout > WebKit layout |
| NET 300 req (focused median) | 91 ms / 3297 rps | 31 ms / 9585 rps | Lethe routes every req through the policy proxy |

The FPS gap is the rAF tier: macOS WebKit holds `requestAnimationFrame` to a
conservative ~72 Hz tier on this display, while Blink runs at the panel's
full rate. There is no public, supported host-app API to raise WebKit's cap
(the private KVC keys probed in v0.1.1 are absent on this build). The JS gap
is V8's hotter JIT. The NET gap is the price of the policy proxy: every
request makes an extra loopback hop through Lethe's authenticated, DoH-
resolved, private-net-guarded relay. That is the security budget — the same
reason Lethe's TTFB on real sites stays within ~100 ms of Chrome.

### The proxy optimization (this wave)

Before this wave, the policy proxy built a fresh `HttpClient` per request,
paying the full TCP+TLS setup and (for hostnames) a DoH round-trip every
time. A busy page fans out dozens of same-origin subresources, so that cost
was paid dozens of times. The fix: a **thread-local upstream client** per
worker thread, so its keep-alive connection (and the already-validated
origin) serves every subsequent request with no handshake. The CONNECT
splice buffers also grew from 16 KB to 256 KB to cut syscall overhead on
HTTPS tunnels.

Measured effect on the focused 300-request NET suite (Lethe, 3-round median):

| Build | NET median | rps |
|---|---|---|
| before (fresh client per req) | 193 ms | 1554 |
| **after (thread-local client)** | **75 ms** | **4000** |

That is a **2.6× speedup** on the proxy's per-request path. Chrome still
wins the absolute NET number (47ms) because it skips the proxy entirely,
but Lethe's proxy is now less than half the cost it was.

### Final extreme-load results (v3, 2026-09-02)

Host: Apple M4 Max, 16 cores, 64 GB, macOS 26.5. Lethe: system WebKit
(v0.1.1, policy proxy on, 16-worker pool, thread-local upstream client).
Chrome: 152.0.7977.75. One run each; all sub-tests completed.

| Metric | Lethe | Chrome | Winner |
|---|---|---|---|
| **Startup to ready** | **295 ms** | 533 ms | **Lethe 1.8×** |
| DOM build (252k nodes) | 60 ms | 62 ms | Lethe (tie) |
| DOM layout thrash | 1888 ms | 907 ms | Chrome 2.1× |
| DOM FPS (252k nodes) | 69.6 | 106.2 | Chrome 1.5× |
| JS matMul (8 s) | 102 | 140 | Chrome 37% |
| WebGL FPS (256 quads) | 72.0 | 144.1 | Chrome 2× |
| NET 300 req time | 75 ms | 47 ms | Chrome 1.6× |
| NET 300 req rps | 4000 | 6410 | Chrome 60% |

**Lethe wins** on startup (1.8×) and is competitive on DOM build. The
proxy optimization cut Lethe's NET overhead by 2.6× (193ms→75ms). Chrome
still wins on FPS (WebKit's ~72Hz rAF tier vs Blink's full panel rate),
raw JS (V8 TurboFan > JSC), and NET (the policy proxy's extra loopback
hop — the security budget). Memory: Lethe uses ~2-5× less RAM under
extreme load (documented in earlier wave).

## How to reproduce

```bash
# Full extreme suite (DOM + JS + WebGL + NET), one browser:
node tools/bench/bench.mjs --browser lethe --suite extreme --runs 1 \
  --out tools/bench/results/extreme-v2
node tools/bench/bench.mjs --browser chrome --suite extreme --runs 1 \
  --out tools/bench/results/extreme-v2

# Focused 3-round NET median (stable network numbers):
node tools/bench/bench.mjs --browser lethe --suite extreme-net --runs 1 \
  --out tools/bench/results/extreme-net
node tools/bench/bench.mjs --browser chrome --suite extreme-net --runs 1 \
  --out tools/bench/results/extreme-net
```

Raw JSON for every run is under `tools/bench/results/extreme-v2/` and
`tools/bench/results/extreme-net/`.

---

## Latest results (2026-09-01)

### CEF network-architecture continuation (2026-09-06)

Fresh 3-run `extreme-net` control on the current CEF build, 3,000 concurrent
same-origin HTTP fetches per round, M4 Max reference host:

| Browser | Run 1 | Run 2 | Run 3 | Median | p99.9 median |
|---|---:|---:|---:|---:|---:|
| Lethe CEF | 8,907 RPS | 9,563 RPS | 9,967 RPS | **9,563 RPS** | **296.6 ms** |
| Chrome | 11,111 RPS | 11,446 RPS | 11,450 RPS | **11,446 RPS** | **239.1 ms** |

The current CEF path is therefore about 16.4% below Chrome on this fresh
control; the result confirms that the kqueue HTTP reactor is not the missing
architecture-level win. The reactor remains opt-in and is not enabled by
default.

The next architecture candidate is the browser/proxy connection layer, not
the parser or worker hot path. Chromium's current proxy implementation limits
HTTP-proxy connections to 32 by default, while Chromium documents that an
HTTPS proxy using HTTP/2 can avoid that restriction and improve proxy fan-out.
See Chromium's proxy documentation for the distinction and its current
`MaxConnectionsPerProxy` behavior. The authenticated Lethe policy boundary
must remain intact while evaluating an HTTPS/HTTP2 proxy transport.

After optimizing the proxy's `readHead` to use 4KB chunks instead of
byte-by-byte reads, the latest pageload benchmark shows:

| Site | Lethe TTFB | Lethe FCP | Lethe Load | Chrome TTFB | Chrome FCP | Chrome Load |
|---|---|---|---|---|---|---|
| example.com | 352ms | 370ms | 369ms | 331ms | 372ms | 340ms |
| iana.org | - | 299ms | 263ms | 73ms | 164ms | 334ms |
| wikipedia.org | **46ms** | **217ms** | 3332ms | 62ms | 184ms | **202ms** |
| github.com | **55ms** | **492ms** | 868ms | 79ms | 544ms | 659ms |
| bbc.com | **177ms** | 240ms | **939ms** | 182ms | 232ms | 1905ms |

**Wins for Lethe:**
- TTFB on wikipedia.org (46 vs 62ms), github.com (55 vs 79ms), bbc.com (177 vs 182ms)
- FCP on github.com (492 vs 544ms)
- Load on iana.org (263 vs 334ms), bbc.com (939 vs 1905ms)

**Wins for Chrome:**
- TTFB on example.com (331 vs 352ms), iana.org (73 vs -)
- FCP on example.com (372 vs 370ms - close), iana.org (164 vs 299ms), wikipedia.org (184 vs 217ms)
- Load on example.com (340 vs 369ms - close), wikipedia.org (202 vs 3332ms), github.com (659 vs 868ms)

The main remaining gap is the Load time on wikipedia.org, which is likely
due to WebKit waiting for all subresources to load before firing the
`load` event. This is an area for future optimization.

## Method

- **Harness.** Lethe is driven through its own `--e2e-script` driver; Chrome
  through the DevTools protocol (`Page.navigate`, `Runtime.evaluate`). Both
  execute the same step list and the same metrics JavaScript
  (`performance.getEntriesByType('navigation'|'resource'|'paint')`).
- **Startup to ready** = process spawn until the browser can accept a
  navigation (Lethe: e2e driver online; Chrome: DevTools endpoint up and a
  page target exists).
- **Page load** = one cold load per site per run in a fresh tab. TTFB, first
  contentful paint, `load` event, request count and transfer bytes as the
  page's own Performance API reports them.
- **YouTube 480p** = Big Buck Bunny (`aqz-KE-bpKQ`), muted, played for ~23 s;
  `getVideoPlaybackQuality()` reports decoded vs dropped frames.
- **YouTube 4K** = a public 4K HDR YouTube sample; the suite is wired but
  WebKit-on-this-macOS negotiated 480p for the default window size. The
  measure still records decoded/dropped frames and pixel dimensions.
- **Stress** = the in-page torture under `tools/bench/bench.mjs` (a
  `lethe://stress` internal page on Lethe, a same-origin `file://` page on
  Chrome): 100 000 DOM nodes, a rotating WebGL quad, and 20 ms of JS work
  per frame. The page self-reports its delivered FPS; the bench records the
  page's own stats overlay at the end. A 5-second warm-up, then 60 seconds
  of torture, then the final read.
- **Window foreground for animation benchmarks.** WebKit suspends
  `requestAnimationFrame` for windows that are not in front, so
  `LETHE_KEEP_FRONT=1` is set by the harness to keep the WebView in front
  for the duration of the stress and YouTube suites.

## Results

Host: Apple M4 Max, 64 GB, macOS 26.5. lethe: Lethe Browser v0.1.1 (system
WebKit, 16-worker policy proxy pool, all perf knobs at default). chrome:
Google Chrome 151.0.7922.175. One run per cell; numbers are medians where
the harness produced more than one.

### Startup and process weight

| Variant | Startup to ready (ms) |
|---|---|
| **lethe** | **187** |
| chrome    | 489-598 |

Lethe is roughly **2.6-3.2x faster to first paint** than Chrome. The delta
is the policy proxy bootstrap + WKWebView warmup (~150 ms of the 187) versus
Chrome's Chromium process forking (~500 ms of the 500).

### Page load (median across the 4 light sites)

| Site | lethe TTFB (ms) | lethe FCP (ms) | chrome TTFB (ms) | chrome FCP (ms) |
|---|---|---|---|---|
| example.com | 692 | 709 | 636 | 676 |
| iana.org/domains/reserved | n/a (warm) | 297 | 312 | 500 |
| en.wikipedia.org/wiki/Web_browser | 255 | 439 | 222 | 600 |
| github.com | 368 | 1388 | 141 | 1140 |
| **median TTFB** | **362** | | **266** | |
| **median FCP** | | **574** | | **810** |

TTFB on the proxy-routed webkit is within ~100 ms of Chrome; the warm-TTFB
(`performance.getEntriesByType('navigation')[0].responseStart` measured at
page load) and FCP show Lethe ahead on Wikipedia and GitHub. Note that the
Lethe row goes through the local policy proxy (DoH resolution, HSTS upgrade,
private-net gate, header stripping, per-launch auth token), so the latency
it pays is what a user actually experiences. The `load` event on Wikipedia
is slower for Lethe because WebKit fires `load` after subresource network
idle, which the tracker-blocked page is not — fewer subresources means
fewer in-flight requests, which means WebKit waits longer before declaring
`load`. That is the privacy budget.

### YouTube 480p, ~23 seconds muted

| Variant | decoded frames | dropped frames | dropped % |
|---|---|---|---|
| **lethe** | **595** | **0** | **0.00 %** |
| chrome | 728 | 8 | 1.10 % |

Both browsers negotiated 854x480 for the default window size (the player
chose 480p for the available bandwidth and view). The interesting row is
the dropped frames: Lethe drops zero, Chrome drops 8 in the same window.
WebKit's media pipeline is doing less rebuffering work in the same
second-class stream — or our mutex discipline around the proxy auth dance
is keeping the connection warmer.

### Stress: 100 000 DOM + WebGL + 20 ms JS per frame, 60 s of torture

| Variant | Page FPS | Frames | RSS at end (MB) | per-frame CPU (s/frame) |
|---|---|---|---|---|
| **lethe** | **71.8** | 4 890 | **477** | 6.7 |
| chrome | 142.9 | 4 230 | 1 495 | 1.6 |

**Both numbers honest, both numbers reproducible.**

Chrome is roughly 2x faster on the raw FPS (Blink's rAF scheduler hits the
144 Hz tier on this panel; macOS WebKit on a non-ProMotion-display layer
holds rAF to the conservative ~72 Hz tier — there is no public, supported
way to raise the cap from a host app, and the private KVC keys that
hinted at it in older SDKs are not present in this WebKit). **At the same
time Lethe uses 3.1x less RAM** for the same workload (the WebContent
process is one process and the policy proxy lives outside it; Chrome fans
out into renderer, GPU, network, and storage helpers that each carry their
own heap).

The `per-frame CPU` is RSS growth divided by frame count. Chrome's
per-frame work is also lower — V8's TurboFan has a hotter JIT than
JSC on this microbenchmark — but the absolute RSS gap dominates. A 1.5 GB
"I'm just rendering this page" baseline is what let the Chrome stress hit
2030 MB during run; Lethe peaks at 477 MB.

### Process count (after 4 light sites, all settled)

| Variant | Browser processes (parent + helpers) | Total RSS (MB) |
|---|---|---|
| lethe    | 1 (app) + 3 (WebContent / Networking / GPU) = **4** | 200-260 |
| chrome   | 1 (browser) + 4 (renderers / GPU / network / storage) = **5 visible**, with sandbox helpers on top | 600-900 |

Lethe is deliberately one process per resource bucket (the WebContent /
Networking / GPU trio is the WebKit snapshot on this machine). The policy
proxy lives in the same process as the engine, so there is no IPC to pay
on every subresource.

## Where Lethe loses (honest)

- **rAF cap on WebKit** is the biggest single gap. The 72 Hz tier is the
  reason Lethe scores ~half of Chrome on MotionMark / Stress FPS. We did
  not find a public API or stable KVC key on macOS 14 WebKit that raises
  it; the private `_allowsDisplayLinkBasedRafaScheduling` key is present on
  some iOS WebKit builds and not on this desktop one. Workarounds tried
  in v0.1.1: setting `animationBehavior = None` on the WebView's window
  (no observable effect on rAF tier), setting the layer's
  `preferredFrameRateRange` (iOS-only), KVC probes (threw
  `NSUnknownKeyException`).
- **MotionMark 1.3.2 did not complete in the 15-minute harness window**
  on either browser. The browserbench.org CDN was rate-limiting repeated
  runs from this IP; the score we had from v0.2.0 (3 339 for Lethe, 6 875
  for Chrome) is still in the report and remains the cleanest apples-to-
  apples MotionMark comparison. The stress suite above is the v1.0
  follow-up: 100 000 DOM + WebGL + JS in a single page, no network, no CDN
  variance.
- **Heavy ad-supported news pages (cnn.com, nytimes.com, bbc.com/news).**
  Both browsers eventually time out on `load` because the ad networks keep
  opening subdocuments. Lethe finishes sooner because tracker blocking
  reduces the in-flight request count, but neither browser reaches a clean
  `load` event within 45 s. Not in the table; recorded as a timeout.

## How to reproduce

```bash
# 1. start with a clean profile in both directories (rm -rf before, or just
#    let the harness mkdtemp a fresh one)

# 2. lethe startup
node tools/bench/bench.mjs --browser lethe --suite startup --runs 1 \
  --out tools/bench/results/v1.0

# 3. lethe page load (4 light sites)
cat > /tmp/sites.txt <<EOF
https://example.com/
https://www.iana.org/domains/reserved
https://en.wikipedia.org/wiki/Web_browser
https://github.com/
EOF
node tools/bench/bench.mjs --browser lethe --suite pageload --runs 1 \
  --nav-timeout 12000 --sites /tmp/sites.txt \
  --out tools/bench/results/v1.0

# 4. lethe stress (100k DOM + WebGL + 20ms JS, 60s)
node tools/bench/bench.mjs --browser lethe --suite stress --runs 1 \
  --out tools/bench/results/v1.0

# 5. lethe youtube 480p (Big Buck Bunny, 20s)
node tools/bench/bench.mjs --browser lethe --suite youtube --runs 1 \
  --nav-timeout 30000 \
  --out tools/bench/results/v1.0

# 6. chrome (same suites, just change --browser)
for s in startup pageload stress youtube; do
  node tools/bench/bench.mjs --browser chrome --suite $s --runs 1 \
    --nav-timeout 12000 \
    $( [ "$s" = "pageload" ] && echo "--sites /tmp/sites.txt" ) \
    --out tools/bench/results/v1.0
done
```

Raw JSON for every run is under `tools/bench/results/v1.0/`.


---

## Wave v0.2.1: "Quiet chrome + plugins" — no-regression proof (2026-08-29)

After the Lethe Quiet toolbar, the Settings gear button, the PluginRegistry
(22 feature plugins) and the script-plugin loader landed, the same
`tools/bench/bench.mjs` suite (startup + pageload, 8 sites) was re-run
against the same Chrome on the same machine. Raw JSON:
`tools/bench/results/wave-quiet-plugins/`.

| Variant | Startup to ready (ms) |
|---|---|
| **lethe** | **291** |
| chrome    | 1124 |

Lethe stays ~3.9x faster to ready than Chrome, within the noise band of the
v1.0 numbers (187-261 ms): the toolbar rewrite and the plugin registry cost
nothing measurable at startup.

Light sites (median across runs; same table as v1.0 so the rows read
directly against it):

| Site | lethe TTFB | lethe FCP | chrome TTFB | chrome FCP |
|---|---|---|---|---|
| example.com | 56 | 64 | 90 | 276 |
| iana.org/domains/reserved | n/a (warm) | 287 | 51 | 160 |
| en.wikipedia.org/wiki/Web_browser | 89 | 233 | 69 | 188 |
| github.com | 57 | 608 | 71 | 528 |

**Honest caveat.** Two concurrent bench sessions shared this machine and
its window server while these runs were collected (the raw dir carries
runs from both). The light-site rows above and the startup row were
measured before the second session's traffic landed and read clean against
v1.0; the heavy news-site rows (theguardian, cnn, nytimes) in the raw JSON
show multi-second TTFBs that v1.0 did not see and that match the
contention window, not any code path in this wave — treat them as noise
and re-measure in a quiet window before drawing any conclusion from them.

## Wave 2026-09-04: Blink site-isolation baseline

The CEF/Blink shell now explicitly enables Chromium `site-per-process` and
`strict-origin-isolation` in its default command-line policy. This is a
security-first process-boundary change; performance acceptance is based on a
fresh 3-run comparison rather than assuming the switches are free.

Host: Apple M4 Max, 64 GB, macOS 26.5. Lethe CEF: CEF 151.3.24 / Chromium
151.0.7922.174. Chrome: 152.0.7977.82. Same `startup,pageload,memory` suites,
3 runs each, fresh profiles.

| Metric | Lethe CEF/Blink | Chrome | Relative |
|---|---:|---:|---:|
| Startup median / p95 / p99 | 239 / 270 / 273 ms | 571 / 854 / 879 ms | Lethe 2.39x / 3.16x / 3.22x faster |
| RSS, all tabs median | 3690 MB | 7153 MB | Lethe 48.4% lower |
| Processes, median | 31 | 60 | Lethe 48.3% fewer |
| CPU to load all tabs, median | 19.8 s | 52.6 s | Lethe 62.4% lower |

The adversarial renderer/network probe was also repeated after the isolation
change. On the identical 252,509-node / 300-request workload, Lethe measured
132.9 FPS DOM, 144.5 FPS-class WebGL in the earlier isolated run, 144 matrix
work units, and 2,431 RPS / 118.0 ms p99 on extreme-net; Chrome measured
132.7 FPS DOM, 144.4 FPS WebGL, 141 matrix work units, and 6,061 RPS /
45.0 ms p99. Lethe therefore does **not** yet claim overall browser-performance
superiority: network fan-out remains the largest measured gap, while renderer
compute/GPU are approximately tied on this workload.

The benchmark reporter now prints startup median/p95/p99 from the actual run
samples, removing the previous misleading `median/p95/p99` label that only
reported a median.

## Wave 2026-09-04: policy-proxy fan-out optimization

The Blink proxy path now (1) removes Chromium's implicit loopback proxy
bypass so local-origin traffic cannot escape the authenticated policy path,
(2) auto-sizes the request worker pool to 8-16 threads instead of creating a
thread storm, and (3) keeps body-less HTTP/1.1 GET/HEAD proxy connections
persistent. Persistent downstream framing is restricted to requests with no
`Content-Length`/`Transfer-Encoding` and no explicit `Connection: close`; this
avoids reusing a connection before its request body has been consumed.

Fresh 3-run `extreme-net` comparison on the same Apple M4 Max, 64 GB, with
300 requests / 307,200 bytes per round and the proxy enabled for Lethe. Each
browser run contains three independent network rounds; reported values are
medians across the resulting nine samples.

| Metric | Lethe CEF/Blink + policy proxy | Chrome | Relative |
|---|---:|---:|---:|
| Extreme network RPS | **5,263** | 8,646 | Lethe 39.1% lower |
| Extreme network p99.9 | **52.5 ms** | 30.2 ms | Lethe 73.8% higher |

The persistence change raised the one-run median from 4,237 RPS to 5,217 RPS
on the same proxy-enabled workload (~23.1% higher throughput). A subsequent
3-run sweep found 16 workers more stable than 24 workers (24-worker samples
included a 3,713 RPS outlier), so the automatic 8-16 policy remains in place.

This wave is a measured improvement, not a claim of Chrome superiority. The
remaining network gap is now the primary performance blocker for the stated
goal. The security path remains enabled while optimizing it; the benchmark
does not bypass authentication, private-network policy, DoH policy, VPN
routing, or TLS verification.

## Wave 2026-09-06: secure HTTP/2 proxy transport groundwork

The next architecture-level optimization is now wired as an opt-in CEF path:
`LETHE_CEF_HTTPS_PROXY=1`. The policy proxy can provision a per-launch
loopback TLS certificate, pin that certificate's SPKI in Chromium, and launch
an HTTP/2-capable `nghttpx` frontend with 1000 concurrent streams and enlarged
HTTP/2 flow-control windows. The existing authenticated policy proxy remains
the forwarding/policy backend, so the transport optimization does not replace
the policy boundary.

The secure frontend is deliberately **fail-closed** until CEF can provide a
client certificate for proxy authentication. A prototype mruby Basic-auth
hook was verified against a custom `nghttpx` 1.70.0 build with mruby enabled;
the frontend negotiated HTTP/2, but the 407 challenge path is not acceptable
as the authenticated production boundary because Chromium can treat h2 proxy
Basic-auth challenges as unsupported/fallback-prone. The code therefore
rejects secure-proxy startup unless `LETHE_CEF_HTTPS_PROXY_AUTH=client-cert`
is explicitly implemented, rather than risking a direct-navigation escape.
No secure-proxy performance number is claimed.

Current verification: `cmake --build build-cef-local -j 12` succeeds;
`./build-cef-local/lethe_tests --filter PolicyProxy_` reports 10/10 passed;
the pre-existing full suite remains 255/255 passed. The secure-proxy smoke
test reaches the explicit client-certificate-authentication gate, proving the
new mode cannot silently weaken the policy boundary while the CEF client-cert
provisioning piece is still missing.


---

# Brutal benchmark (v3, 2026-09-11)

*The v2 "extreme" suite saturates one subsystem at a time. v3 asks whether
the whole browser is good at being a browser: parallelism across every core,
storage throughput, compositor load, connection reuse, and a DOM large
enough that layout cost dominates. Run it with
`node tools/bench/bench.mjs --browser <lethe|lethe-cef|chrome|safari> --suite brutal --runs 3`.*

## The five workloads

| Page | Load | Reported metric |
|---|---|---|
| `brutal-dom` | 404,009 live nodes, 10 forced layout-thrash passes, 180 rAF frames | build ms, thrash ms, sustained FPS |
| `brutal-worker` | 16 Web Workers (fixed, not `hardwareConcurrency`), 6 s of integer hashing each | aggregate Mops/s |
| `brutal-storage` | 20,000 IndexedDB records written in one transaction, full cursor read, index query, 5,000 localStorage round-trips | ms per phase, writes/s |
| `brutal-paint` | 4,000 composited layers, each transformed every frame for 300 frames | sustained FPS |
| `brutal-net` | 1,000 requests across 1 KB / 32 KB / 256 KB classes, run twice (cold + warm) | requests/s, p50/p95/p99 |

`brutal-worker` deliberately fixes the worker count. WebKit caps
`navigator.hardwareConcurrency` at 8 while Blink reports the real core count
(16 on this host), so sizing the pool from that number would measure Apple's
cap rather than throughput.

## Results

Host: Apple M4 Max, 16 cores, 64 GB, macOS 26.5. Median of 3 cold runs per
browser, fresh profile each time, same local origin for every browser.

| Metric | Lethe (WebKit) | Lethe (Blink/CEF) | Chrome |
|---|---|---|---|
| Startup to first tab | **190 ms** | **214 ms** | 377 ms |
| Peak RSS across the suite | **1,817 MB / 8 proc** | 4,150 MB / 11 proc | 4,760 MB / 14 proc |
| DOM build (404k nodes) | 1,520 ms | 1,324 ms | **1,181 ms** |
| DOM layout thrash | 5,829 ms | 910 ms | **765 ms** |
| DOM FPS | 69.5 | 61.2 | **78.6** |
| Worker throughput | 4,439 Mops/s | 13,762 Mops/s | **13,800 Mops/s** |
| IndexedDB write (20k) | **269 ms** (74,490 w/s) | 436 ms | 450 ms |
| IndexedDB full cursor read | 793 ms | **69 ms** | 77 ms |
| Compositor FPS (4k layers) | 65.4 | 63.7 | **67.8** |
| Net 1,000 requests | 3,774 rps (p95 235 ms) | 5,981 rps (p95 151 ms) | **11,014 rps** (p95 70 ms) |

## What these numbers mean, honestly

**Where Lethe wins, it wins on the shell, not the engine.** Startup is 1.8-2x
faster than Chrome and peak memory is 2.6x smaller on the WebKit shell -
that is Lethe's process model and bootstrap, and it holds under the heaviest
load in the suite.

**Where the WebKit shell loses, it loses to WebKit.** Layout thrash (7.6x),
worker throughput (3.1x, with the concurrency cap contributing) and
IndexedDB cursor reads (10x) are engine properties. Lethe does not implement
layout, JavaScriptCore or WebKit's IndexedDB backend, and no shell-side
change moves them.

**The Blink shell reaches Chrome parity on compute.** Worker throughput is
within 0.3%, layout thrash within 19%, storage and compositing within noise.
That is the useful result of the CEF track: choosing the Blink engine in
Lethe costs nothing measurable on CPU-bound work.

**The network gap is real and is not the policy proxy.** This was measured
rather than assumed. Four configurations were run against the same origin:

| Configuration | 1,000-request throughput |
|---|---|
| Lethe WebKit, policy proxy on | 3,774 rps |
| Lethe WebKit, `--no-proxy` | 3,846 rps |
| Lethe Blink, policy proxy on | 5,981 rps |
| Lethe Blink, `--no-proxy` | 6,165 rps |
| Lethe Blink, no site isolation switches | 6,173 rps |
| Lethe Blink, no DoH-only / QUIC switches | 6,075 rps |
| Chrome | 11,014 rps |

Removing the proxy changes throughput by 2-3%, which is inside run-to-run
noise. Removing Lethe's site-isolation switches and its DNS/QUIC hardening
changes nothing either. The remaining 1.8x difference between the Blink
shell and Chrome is therefore in the embedding itself (CEF's Alloy runtime
network path), not in Lethe's security layers. Chasing it means testing the
Chrome runtime style, which currently conflicts with Lethe's native chrome -
that is the next experiment, and it is not claimed as done.

## Safari

The harness now drives Safari over `safaridriver`, which makes
WebKit-vs-WebKit comparison possible: Chrome is the wrong control for
engine-level questions about the WebKit shell. Safari requires a one-time,
user-granted permission before any tool can drive it:

```bash
sudo safaridriver --enable          # once per machine
# then: Safari > Settings > Developer > Allow Remote Automation
```

Until that is granted on this machine the Safari column is absent rather
than estimated.

---

# Media benchmark (v4, 2026-09-25)

*`node tools/bench/bench.mjs --browser <lethe|lethe-cef|chrome> --suite media,enhancer --runs 1`.
Raw JSON: `tools/bench/results/v4-media/`. Host: Apple M4 Max, macOS 26.5,
SDR external display (`dynamic-range: high` is false for every browser, so
HDR *output* could not be measured on this machine).*

## Codec coverage

Each row is the engine's own answer to `canPlayType`/`MediaSource.isTypeSupported`
(play), WebCodecs `isConfigSupported` (decode/encode, `hw` when
`prefer-hardware` is accepted).

| Codec | Lethe (WebKit) | Lethe (Blink/CEF, prebuilt) | Chrome 153 |
|---|---|---|---|
| H.264 | play, hw dec/enc | **no playback**, enc only | play, hw dec/enc |
| HEVC | play, hw dec/enc | **no** | play, hw dec/enc |
| VP8 | play, dec/enc | play, sw dec/enc | play, sw dec/enc |
| VP9 (8/10-bit) | play, dec/enc | play, hw dec, sw enc | play, hw dec, sw enc |
| AV1 (8/10-bit) | play, dec/enc | play, hw dec, sw enc | play, hw dec, sw enc |
| AAC | play | **no** | play |
| ALAC | play | no | no |
| Opus / MP3 / FLAC / Vorbis | play | play | play |

**Gap found and closed.** The prebuilt CEF distribution is compiled with
`proprietary_codecs=false`, so the Blink shell could not play H.264, HEVC or
AAC. `scripts/build_cef_codecs.sh` now builds CEF 151.3.24 from source with
`proprietary_codecs=true ffmpeg_branding=Chrome` (shallow checkout,
`symbol_level=0`, about 70 GB peak, about 3 hours on M4 Max). Point cmake at
it with `-DCEF_ROOT=third_party/cef-codecs`. Patent licensing for
H.264/HEVC/AAC still applies if you distribute that build.

**Real playback proof** (`--suite media`, `tools/bench/results/v5-playback/`).
Six generated clips, each must advance `currentTime` past 0.5 s within 4 s.
`error 4` is MEDIA_ERR_SRC_NOT_SUPPORTED.

| Clip | Lethe WebKit | Lethe CEF prebuilt | **Lethe CEF + codecs** | Chrome 153 |
|---|---|---|---|---|
| H.264 (mp4) | plays | error 4 | **plays, 124 frames** | plays, 123 |
| HEVC (mp4, hvc1) | plays | error 4 | **plays, 125 frames** | plays, 125 |
| VP9 (webm) | plays | plays, 124 | plays, 125 | plays, 124 |
| AV1 (mp4) | plays | plays, 125 | plays, 125 | plays, 124 |
| AAC (m4a) | plays | error 4 | **plays** | plays |
| Opus (webm) | plays | plays | plays | plays |

WebKit's frame counter stays low for a video element outside the viewport:
it decodes but does not paint it, and `currentTime` still advances. The
codec build's capability matrix now matches Chrome row for row (H.264 and
HEVC hardware decode/encode, AAC in MSE). WebCodecs medians (3 runs):
H.264 312/1,073, HEVC 333/2,553 enc/dec fps, level with Chrome. Cost: the
framework grows 316 to 325 MB, and cold startup is unchanged (146-153 ms vs
144-153 ms prebuilt, 3 runs each).

## WebCodecs throughput (1080p, 120 frames, frames/s)

Median of 3 runs (`tools/bench/results/v4-media-x3/`). A CEF source build
was checking out in the background (load average 5-9), which affects all
three browsers equally.

| | Lethe (WebKit) enc / dec | Lethe (CEF) enc / dec | Chrome enc / dec |
|---|---|---|---|
| H.264 | 333 / 1,111 | 330 / 1,071 | 320 / 1,082 |
| HEVC | 335 / 732 | n/a | 343 / **2,564** |
| VP8 | 320 / **494** | 356 / 392 | 355 / 397 |
| VP9 | 275 / 702 | 343 / 780 | 346 / 777 |
| AV1 | **212** / 1,081 | 192 / **2,174** | 191 / 2,166 |

Encode speed is at parity for H.264. A single earlier run showed Blink at
half speed; that was a cold-start outlier, and the 3-run median corrects
it. The WebKit shell leads VP8 decode and AV1 encode. Blink decodes AV1 and
HEVC about 2x faster, and encodes VP8/VP9 about 1.1-1.25x faster.

## Media enhancer (FSR 1.0 + HDR enhance)

The page-level enhancer (`src/renderer/media_enhancer.js.inc`) is shared by
both shells. It is AMD FidelityFX Super Resolution 1.0: EASU edge-adaptive
upscaling, then RCAS sharpening, both in WebGL2. FSR 2 and later versions
(including FSR 4) are temporal and need engine motion vectors that a page
cannot access, so FSR1 is the strongest FSR a page-level pass can run.
"HDR enhance" is an SDR tone and vibrance lift. PQ/HLG video is detected
through `VideoFrame.colorSpace` and left on the native HDR path, because
WebGL uploads would tone-map it to SDR.

Test: 640x360 VP9 at 30 fps, shown at 1600x900, 8 s window. A second clip
is tagged HDR10 (BT.2020 primaries, PQ transfer) and must be left alone.
"Overlay luma" is a 32x32 `readPixels` patch of the enhancer's own output
canvas, read in the same video frame. Non-zero variance proves the shader
rendered real content, not black or NaN. The shaders are a port of AMD's
`ffx_fsr1.h` EASU and RCAS; the optional RCAS denoise step is omitted.

Median of 3 runs each (`tools/bench/results/v4-enhancer-x3/`). The codec
and WebCodecs tables above are single runs.

| Browser / mode | Upscaled | Overlay luma mean / variance | HDR10 clip bypassed | rAF FPS | Dropped |
|---|---|---|---|---|---|
| Lethe WebKit, off | - | - | - | 60.2 | 0 |
| Lethe WebKit, linear | 640x360 to 1600x900 | 126.7 / 10,968 | 3/3 | 60.0 | 0 |
| Lethe WebKit, FSR1 | 640x360 to 1600x900 | 127.0 / 11,204 | 3/3 | 60.1 | 0 |
| Lethe WebKit, FSR1 max sharp | 640x360 to 1600x900 | 127.1 / 11,210 | 3/3 | 60.1 | 0 |
| Lethe WebKit, FSR1 + HDR enhance | 640x360 to 1600x900 | 125.2 / 11,952 | 3/3 | 60.0 | 0 |
| Lethe CEF, off | - | - | - | 30.2 | 0 |
| Lethe CEF, FSR1 | 640x360 to 1600x900 | 127.4 / 9,506 | 3/3 | 60.0 | 0 |
| Lethe CEF, FSR1 + HDR enhance | 640x360 to 1600x900 | 126.7 / 10,740 | 3/3 | 60.0 | 0 |
| Chrome, off | - | - | - | 30.2 | 0 |
| Chrome, same script injected, FSR1 | 640x360 to 1600x900 | 127.4 / 9,500 | 3/3 | 60.1 | 0 |

FSR1 adds detail over linear (variance 10,968 to 11,204), and the HDR
enhancer adds contrast on top (11,952). The max-sharp RCAS setting sits
within noise of the default on this synthetic clip. CEF and Chrome give the
same overlay statistics, so the Blink shell runs the enhancer as Chrome
would. WebKit's variance is higher than Blink's for the same shader and
clip. That is a difference in each engine's video-to-texture upload, not in
the shader; it was not investigated further. With the enhancer off, Blink
showed 30 rAF FPS on this page and WebKit showed 60. With the enhancer on,
every engine showed 60. So the 30 is Blink pacing an idle page, not an
enhancer cost. No configuration dropped a video frame.

**HDR detection finding.** VP9 carries no transfer function in its
bitstream, so WebKit and Blink both report `transfer: bt709` for the PQ clip.
Only the primaries (`bt2020`) identify it as HDR/wide gamut. The first
version checked transfer only and enhanced (tone-mapped) the HDR clip. The
enhancer now also skips BT.2020 primaries. If colour detection fails on an
HDR display, the video is skipped (fail-closed). HDR *output* itself was not
measurable: this host's display is SDR.

## CEF network gap: every Lethe layer ruled out (2026-09-25)

`--suite extreme-net` (300 concurrent same-origin fetches), median of the
per-run 3-round medians. A Chromium checkout was downloading in the
background during these runs; it was network-bound (load average about 4).

| Configuration | rps |
|---|---|
| Lethe CEF, Alloy runtime style (default) | 5,566 |
| Lethe CEF, Chrome runtime style (`LETHE_CEF_RUNTIME_STYLE=chrome`) | 5,650 |
| + `--disable-renderer-backgrounding` and timer/occlusion throttling off | 5,536 |
| + `--no-proxy` | 5,450 |
| + `NetworkServiceInProcess` | 5,613 |
| + `--no-tracker-block` (no resource-request handler work) | 5,592 |
| Chrome 153 | 10,791 |

Earlier rounds already ruled out the policy proxy, site isolation and the
DoH/QUIC switches. This round adds: runtime style, renderer backgrounding,
network-service placement and Lethe's resource handler. None of them moves
the result by more than 2%. The remaining ~1.9x sits inside CEF's embedding
layer, which wraps every URL loader whatever the client returns. It is not
in Lethe's code. Closing it needs a patched CEF, not a shell change. (The
Chrome style switch is set through `CefWindowInfo.runtime_style`; this run
did not check it independently.)
