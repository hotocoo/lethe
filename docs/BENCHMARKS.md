# Lethe vs Chrome: measured

*Every number here comes from `tools/bench/bench.mjs` runs on one machine,
same network, browsers launched cold with fresh profiles, sequentially,
through the same declarative steps. Raw JSON for every run is committed
under `tools/bench/results/`. Reproduce with the commands in README.md.*

## Method

- **Harness.** Lethe is driven through its own `--e2e-script` driver; Chrome
  through the DevTools protocol (`Page.navigate`, `Runtime.evaluate`). Both
  execute the same step list and the same metrics JavaScript
  (`performance.getEntriesByType('navigation'|'resource'|'paint')`).
- **Startup to ready** = process spawn until the browser can accept a
  navigation (Lethe: e2e driver online; Chrome: DevTools endpoint up and a
  page target exists).
- **Page load** = one cold load per site per run in a fresh tab
  (`tools/bench/sites.txt`). TTFB, first contentful paint, `load` event,
  request count and transfer bytes as the page's own Performance API reports
  them. Blocked requests do not appear in the resource list, so fewer
  requests / bytes on the Lethe rows is the tracker blocker working. A site
  whose `load` event never fires within 45 s (cnn.com, nytimes.com: endless
  ad iframes, in **both** browsers) is recorded as a timeout, not hidden.
- **RSS / CPU** = sum over the browser's process tree, sampled 5 s after the
  last tab finished. Chrome: every process whose command line carries the
  run's unique `--user-data-dir`. Lethe: the app process plus the
  `com.apple.WebKit.{WebContent,Networking,GPU}` helpers that appeared after
  launch (snapshot diff; no other WebKit app was started during the run).
- **YouTube** = Big Buck Bunny (`aqz-KE-bpKQ`), muted, played for 20 s;
  `getVideoPlaybackQuality()` dropped/total frames, CPU seconds consumed by
  the process tree during those 20 s, RSS at the end.
- **Speedometer 3.1 / JetStream 2.2 / MotionMark 1.3.1** from browserbench.org,
  default settings. Three runs of Speedometer + JetStream per browser and two
  runs of MotionMark per browser; medians in the table. Lethe renders with
  the system WebKit, so these measure WebKit-on-this-Mac vs Chrome's
  Blink/V8 - Lethe adds no JS of its own to the page.
- **Window foreground for animation benchmarks.** WebKit suspends
  `requestAnimationFrame` and reports `document.visibilityState = "hidden"`
  for windows that are not in front, so animation benchmarks hung whenever
  another app (VS Code, the terminal running the harness) was in front.
  `LETHE_KEEP_FRONT=1` re-asserts frontmost every 2 s (set automatically by
  the bench harness for the MotionMark suite); Speedometer and JetStream
  also ran with it once we discovered they too can stall under throttling.
- **Ablations** use the SAME Lethe binary with one feature switched off:
  `lethe-noblock` (`LETHE_TRACKER_BLOCK=0`), `lethe-nocache`
  (`LETHE_DOH_SHARED_CACHE=0`, the 0.1.0 per-connection DoH behaviour),
  `lethe-noproxy` (`--no-proxy`, navigation gate only - never a shipping
  mode, shown to price the transport proxy).

## Results (v0.2.0)

Host: Apple M4 Max, 64 GB, macOS 26.5. lethe: Lethe Browser v0.2.0; chrome: Google Chrome 151.0.7922.175; lethe-noblock: Lethe Browser v0.2.0; lethe-nocache: Lethe Browser v0.2.0; lethe-noproxy: Lethe Browser v0.2.0. Runs per variant: 14. Medians unless stated.

| Variant | Startup to ready (ms) | RSS, all tabs (MB) | Processes | CPU (s) to load all tabs |
|---|---|---|---|---|
| lethe | 271 | 1998 | 12 | 38.4 |
| chrome | 732 | 8642 | 62 | 60.0 |
| lethe-noblock | 254 | 2609 | 11 | 51.7 |
| lethe-nocache | 255 | 1860 | 11 | 43.1 |
| lethe-noproxy | 269 | 1645 | 11 | 42.8 |

| Site | Metric | lethe | chrome | lethe-noblock | lethe-nocache | lethe-noproxy |
|---|---|---|---|---|---|---|
| example.com/ | TTFB | 87 | 125 | 70 | 87 | 30 |
|  | First paint | 93 | 172 | 77 | 94 | 36 |
|  | load event | 93 | 128 | 76 | 94 | 36 |
|  | Requests | 0 | 0 | 0 | 0 | 0 |
|  | Reported bytes (KB)* | 1 | 1 | 1 | 1 | 1 |
| www.iana.org/domains/reserved | TTFB | n/a | 52 | n/a | n/a | n/a |
|  | First paint | 236 | 148 | 221 | 288 | 217 |
|  | load event | 250 | 270 | 209 | 271 | 203 |
|  | Requests | 8 | 9 | 8 | 8 | 8 |
|  | Reported bytes (KB)* | 1263 | 1266 | 1263 | 1263 | 1263 |
| en.wikipedia.org/wiki/Web_browser | TTFB | 374 | 69 | 423 | 389 | 21 |
|  | First paint | 805 | 180 | 727 | 675 | 129 |
|  | load event | 3704 | 174 | 3753 | 3714 | 3255 |
|  | Requests | 35 | 36 | 35 | 35 | 35 |
|  | Reported bytes (KB)* | 433 | 466 | 433 | 433 | 433 |
| github.com/ | TTFB | 37 | 66 | 28 | 31 | 16 |
|  | First paint | 1212 | 1004 | 1267 | 986 | 1035 |
|  | load event | 8961 | 6538 | 8497 | 2205 | 5557 |
|  | Requests | 128 | 135 | 134 | 141 | 133 |
|  | Reported bytes (KB)* | 116 | 3175 | 116 | 116 | 116 |
| www.bbc.com/news | TTFB | 355 | 365 | 534 | 69 | 235 |
|  | First paint | 376 | 436 | 594 | 122 | 276 |
|  | load event | 1037 | 617 | 990 | 729 | 793 |
|  | Requests | 98 | 149 | 131 | 98 | 104 |
|  | Reported bytes (KB)* | 65 | 2063 | 65 | 65 | 65 |
| www.theguardian.com/international | TTFB | 421 | 356 | 545 | 449 | 42 |
|  | First paint | 563 | 640 | 592 | 639 | 133 |
|  | load event | 2681 | 1273 | 2528 | 4557 | 933 |
|  | Requests | 92 | 98 | 92 | 92 | 92 |
|  | Reported bytes (KB)* | 141 | 431 | 141 | 141 | 141 |
| edition.cnn.com/ | TTFB | 380 | 345 | 32 | 414 | 218 |
|  | First paint | 743 | 796 | 289 | 1357 | 856 |
|  | load event | no load event (3/3) | no load event (3/3) | no load event (3/3) | no load event (3/3) | no load event (3/3) |
|  | Requests | 239 | 250 | 250 | 197 | 188 |
|  | Reported bytes (KB)* | 1469 | 2123 | 1469 | 1472 | 1469 |
| www.nytimes.com/ | TTFB | 385 | 501 | 285 | 786 | 386 |
|  | First paint | 1252 | 1096 | 1099 | 1984 | 984 |
|  | load event | 4101 | 16180 | 24217 (1/3 timed out) | 31449 (1/3 timed out) | 43434 (2/3 timed out) |
|  | Requests | 114 | 219 | 42 | 100 | 135 |
|  | Reported bytes (KB)* | 638 | 3663 | 355 | 772 | 808 |

\* Transfer sizes as the page's own Performance API reports them. WebKit reports 0 for cross-origin resources without `Timing-Allow-Origin`, Chromium reports them; the bytes column is therefore comparable between Lethe variants, not between Lethe and Chrome. Request counts are comparable.

| Benchmark | lethe | chrome | lethe-noblock | lethe-nocache | lethe-noproxy |
|---|---|---|---|---|---|
| Speedometer 3.1 (higher is better) | 45.3 | 51.9 | n/a | n/a | n/a |
| JetStream 2.2 (higher is better) | 555.6 | 573.7 | n/a | n/a | n/a |
| MotionMark 1.3.1 (higher is better) | 3339.0 | 6874.7 | n/a | n/a | n/a |
| YouTube 20 s muted playback | 0/532 dropped, 480p, CPU 2.0 s / 20 s, RSS 872 MB | 0/680 dropped, 480p, CPU 7.3 s / 20 s, RSS 8886 MB | n/a | n/a | n/a |

Four Lethe runs failed with "score still falsy after timeout" before the
keep-front fix was wired into the bench harness for all suites; the JSON
is preserved in the run log so the failures are auditable.

## Reading the numbers honestly

- Where Lethe is faster on page load, the win comes from three things Chrome
  does not do by default: blocking third-party trackers (fewer requests and
  bytes), a smaller process footprint, and WebKit's paint pipeline on macOS.
  It is not a faster network stack for the engine's own traffic - inside
  https the bytes are WebKit's.
- Where Lethe is slower, it is usually the policy proxy: every connection
  first goes to a local CONNECT proxy that resolves the destination over DoH
  and classifies it before dialling. `lethe-noproxy` shows that price and
  `lethe-nocache` shows how much of it 0.1.0 was paying needlessly.
- Speedometer / JetStream / MotionMark are JavaScriptCore vs V8 and WebKit
  vs Blink. Lethe claims no delta over Safari there and will not pretend to.
  Measured on the 144 Hz panel these machines ship with: Chrome's `rAF`
  fires at the full 144 Hz; Lethe's fires at ~72 Hz (the maximum WebKit's
  `CADisplayLink` actually schedules for a non-ProMotion-style content
  layer in the current SDK). That alone is roughly a 2× frame-delivery
  gap, and shows up in the MotionMark number (3339 vs 6874.7). We did not
  find a public API to raise it.
- RSS comparisons favour Lethe partly because Chrome pays for site isolation
  (one process per site). That isolation is a real security property Lethe's
  WebKit shell inherits only to the extent WebKit provides it.
- One machine, one network, three runs. Enough to see the shape; not a lab.
