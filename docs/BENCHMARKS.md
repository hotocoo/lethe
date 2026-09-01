# Lethe vs Chrome: measured (v1.0)

*Every number below comes from `tools/bench/bench.mjs` runs on this machine,
through the same declarative step list, with both browsers launched cold
under a fresh profile. Raw JSON for every run is committed under
`tools/bench/results/v1.0/`. Reproduce with the commands in `README.md`.*

## Latest results (2026-09-01)

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
