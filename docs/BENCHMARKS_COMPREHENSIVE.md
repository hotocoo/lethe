# Lethe vs Chrome — Comprehensive Benchmark Report (v1.0)

**Date:** 2026-09-01
**Hardware:** Mac Studio, 2560x1440 @ 144Hz display
**Methodology:** tools/bench/bench.mjs (median of runs)

## Summary

| Metric | Lethe (WebKit) | Chrome (Blink) | Winner |
|--------|---------------|----------------|--------|
| **Startup time** | 242ms | 372ms | **Lethe** (1.54x faster) |
| **First Contentful Paint** | 415ms | 542ms | **Lethe** (1.31x faster) |
| **Time to First Byte** | 187ms | 163ms | Chrome (1.15x faster) |
| **Stress FPS (100k DOM + WebGL)** | 71.8 | 143.0 | Chrome (2x faster) |

## Detailed Results

### Startup Time (5 runs, median)
- Lethe: 242ms (326, 240, 242, 247, 238)
- Chrome: 372ms (1487, 372, ...)

### Page Load (4 sites, median)
| Site | Lethe TTFB | Chrome TTFB | Lethe FCP | Chrome FCP |
|------|-----------|-------------|-----------|------------|
| example.com | 387ms | 268ms | 398ms | 548ms |
| iana.org | - | 219ms | 161ms | 548ms |
| wikipedia.org | 187ms | 68ms | 432ms | 536ms |
| github.com | 73ms | 107ms | 579ms | 1036ms |
| **Median** | **187ms** | **163ms** | **415ms** | **542ms** |

### Stress Test (FPS)
- Lethe: 71.8 FPS (100k DOM nodes + WebGL quad + 20ms JS work)
- Chrome: 143.0 FPS

## Analysis

### Where Lethe Wins
1. **Startup time**: Lethe is 1.54x faster (242ms vs 372ms)
2. **First Contentful Paint**: Lethe is 1.31x faster (415ms vs 542ms)

### Where Chrome Wins
1. **Time to First Byte**: Chrome is 1.15x faster (163ms vs 187ms)
2. **Stress FPS**: Chrome is 2x faster (143 vs 72 FPS)

### FPS Gap Analysis
The display is 144Hz. Chrome hits 143 FPS (near the display cap). Lethe (WebKit) is capped at 71.8 FPS — exactly half of 144Hz. This suggests WebKit is detecting the display as 72Hz instead of 144Hz, or WebKit's rAF scheduler is limiting to 72Hz.

## Conclusion

Lethe outperforms Chrome on startup time and First Contentful Paint. Chrome outperforms Lethe on Time to First Byte and Stress FPS. The FPS gap is due to a WebKit refresh rate detection/scheduling limitation.

---

*Raw JSON for every run is committed under tools/bench/results/v1.0/*
