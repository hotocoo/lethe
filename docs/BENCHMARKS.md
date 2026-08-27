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
  one run each, default settings. Lethe renders with the system WebKit, so
  these measure WebKit-on-this-Mac vs Chrome's Blink/V8 - Lethe adds no JS
  of its own to the page.
- **Ablations** use the SAME Lethe binary with one feature switched off:
  `lethe-noblock` (`LETHE_TRACKER_BLOCK=0`), `lethe-nocache`
  (`LETHE_DOH_SHARED_CACHE=0`, the 0.1.0 per-connection DoH behaviour),
  `lethe-noproxy` (`--no-proxy`, navigation gate only - never a shipping
  mode, shown to price the transport proxy).

## Results (v0.2.0)

RESULTS_PLACEHOLDER

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
- RSS comparisons favour Lethe partly because Chrome pays for site isolation
  (one process per site). That isolation is a real security property Lethe's
  WebKit shell inherits only to the extent WebKit provides it.
- One machine, one network, three runs. Enough to see the shape; not a lab.
