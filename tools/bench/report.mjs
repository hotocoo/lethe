#!/usr/bin/env node
// report.mjs - turn a results directory into Markdown tables (medians).
//   node tools/bench/report.mjs tools/bench/results/<dir> [> docs/BENCHMARKS.md section]
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2];
if (!dir) { console.error('usage: report.mjs <results-dir>'); process.exit(2); }
const docs = readdirSync(dir).filter(f => f.endsWith('.json')).map(f => JSON.parse(readFileSync(join(dir, f), 'utf8')));
if (!docs.length) { console.error('no results'); process.exit(1); }

const median = a => { const v = a.filter(x => typeof x === 'number' && !Number.isNaN(x)).sort((x, y) => x - y); return v.length ? (v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2) : null; };
const percentile = (a, p) => { const v = a.filter(x => typeof x === 'number' && !Number.isNaN(x)).sort((x, y) => x - y); if (!v.length) return null; const i = (v.length - 1) * p; const lo = Math.floor(i), hi = Math.ceil(i); return lo === hi ? v[lo] : v[lo] + (v[hi] - v[lo]) * (i - lo); };
const fmt = (v, d = 0) => v === null || v === undefined ? 'n/a' : Number(v).toFixed(d);
const fmtDist = (a, d = 0) => `${fmt(median(a), d)}/${fmt(percentile(a, 0.95), d)}/${fmt(percentile(a, 0.99), d)}`;
const labels = [...new Set(docs.map(d => d.label || d.browser))];
const by = l => docs.filter(d => (d.label || d.browser) === l);
const host = docs[0].host;

let out = '';
out += `Host: ${host.cpu}, ${host.memoryGb} GB, ${host.os}. `;
out += labels.map(l => `${l}: ${by(l)[0].version}`).join('; ') + `. Runs per variant: ${Math.max(...labels.map(l => by(l).length))}. Medians unless stated; latency distributions include p95/p99 where available.\n\n`;

// Startup + memory + cpu
out += '| Variant | Startup to ready (ms median/p95/p99) | RSS, all tabs (MB) | Processes | CPU (s) to load all tabs |\n|---|---|---|---|---|\n';
for (const l of labels) {
  const ds = by(l);
  const mem = ds.map(d => d.memory.find(m => m.name === 'memory:all-tabs')).filter(Boolean);
  out += `| ${l} | ${fmtDist(ds.map(d => d.startupMs))} | ${fmt(median(mem.map(m => m.rssMb)))} | ${fmt(median(mem.map(m => m.processes)))} | ${fmt(median(mem.map(m => m.cpuSec)), 1)} |\n`;
}
out += '\n';

// Page load per site
const sites = docs[0].sites || [];
if (sites.length) {
  out += '| Site | Metric | ' + labels.join(' | ') + ' |\n|---|---|' + labels.map(() => '---').join('|') + '|\n';
  for (const site of sites) {
    for (const [metric, key, d] of [['TTFB', 'ttfb', 0], ['First paint', 'fcp', 0], ['load event', 'load', 0], ['Requests', 'resources', 0], ['Reported bytes (KB)*', 'bytes', 0]]) {
      const cells = labels.map(l => {
        const ps = by(l).flatMap(doc => doc.pageload.filter(p => p.url === site || (p.url && site && p.url.replace(/\/$/, '') === site.replace(/\/$/, ''))));
        if (!ps.length) return 'n/a';
        if (key === 'load') { const timeouts = ps.filter(p => !p.load).length; const m = median(ps.map(p => p.load)); return m === null ? `no load event (${timeouts}/${ps.length})` : fmt(m) + (timeouts ? ` (${timeouts}/${ps.length} timed out)` : ''); }
        if (key === 'bytes') return fmt(median(ps.map(p => p.bytes)) / 1024);
        return fmt(median(ps.map(p => p[key])), d);
      });
      out += `| ${metric === 'TTFB' ? site.replace(/^https?:\/\//, '') : ''} | ${metric} | ${cells.join(' | ')} |\n`;
    }
  }
  out += '\n\\* Transfer sizes as the page\'s own Performance API reports them. WebKit reports 0 for cross-origin resources without `Timing-Allow-Origin`, Chromium reports them; the bytes column is therefore comparable between Lethe variants, not between Lethe and Chrome. Request counts are comparable.\n\n';
}

// Benchmarks
const rows = [];
for (const [name, key] of [['Speedometer 3.1 (higher is better)', 'speedometer'], ['JetStream 2.2 (higher is better)', 'jetstream'], ['MotionMark 1.3.1 (higher is better)', 'motionmark']]) {
  const vals = labels.map(l => { const v = by(l).map(d => parseFloat(String(d[key] ?? '').replace(/[^\d.]/g, ''))).filter(x => !Number.isNaN(x)); return v.length ? fmt(median(v), 1) : null; });
  if (vals.some(v => v !== null)) rows.push(`| ${name} | ${vals.map(v => v ?? 'n/a').join(' | ')} |`);
}
const yt = labels.map(l => { const v = by(l).map(d => d.youtube).filter(y => y && !y.error); if (!v.length) return null;
  const dropped = median(v.map(y => y.droppedFrames)), total = median(v.map(y => y.totalFrames));
  // A sample taken after the process already exited (early harness race) has fewer processes / less CPU than at start: discard it.
  const marks = by(l).map(d => { const a = d.memory.find(m => m.name === 'youtube:start'), b = d.memory.find(m => m.name === 'youtube:end'); return a && b && b.processes >= 3 && b.cpuSec >= a.cpuSec ? { cpu: b.cpuSec - a.cpuSec, rss: b.rssMb } : null; }).filter(Boolean);
  return `${fmt(dropped)}/${fmt(total)} dropped, ${fmt(median(v.map(y => y.height)))}p, CPU ${fmt(median(marks.map(m => m.cpu)), 1)} s / 20 s, RSS ${fmt(median(marks.map(m => m.rss)))} MB`; });
if (yt.some(v => v)) rows.push(`| YouTube 20 s muted playback | ${yt.map(v => v ?? 'n/a').join(' | ')} |`);

// Extreme synthetic workloads. Keep these metrics separate from the public
// browser benchmarks: they are intentionally adversarial and exist to expose
// renderer/network scaling behavior. Parse the browser-reported text rather
// than inferring performance from wall-clock duration alone.
const extremeMetric = (label, field, re, digits = 1) => {
  const vals = labels.map(l => {
    // extreme-net runs three independent rounds and stores them in
    // `netRounds`; fold those into the sample set instead of silently
    // reporting n/a because `extreme.net` is reserved for the single-run
    // extreme suite. Other extreme metrics remain one sample per run.
    const samples = by(l).flatMap(d => {
      if (!d.extreme) return [];
      if (field === 'net' && Array.isArray(d.extreme.netRounds)) {
        return d.extreme.netRounds.filter(v => typeof v === 'string');
      }
      return typeof d.extreme[field] === 'string' ? [d.extreme[field]] : [];
    });
    const parsed = samples.map(v => { const m = v.match(re); return m ? Number(m[1]) : null; })
      .filter(v => typeof v === 'number' && Number.isFinite(v));
    return parsed.length ? `${fmt(median(parsed), digits)} (n=${parsed.length})` : 'n/a';
  });
  if (vals.some(v => v !== 'n/a')) rows.push(`| ${label} | ${vals.join(' | ')} |`);
};
extremeMetric('Extreme DOM FPS (higher is better)', 'dom', /fps=([0-9.]+)/);
extremeMetric('Extreme DOM build (ms, lower is better)', 'dom', /build=([0-9.]+)/);
extremeMetric('Extreme DOM layout thrash (ms, lower is better)', 'dom', /thrash=([0-9.]+)/);
extremeMetric('Extreme JS workload (ms, lower is better)', 'js', /t=([0-9.]+)/);
extremeMetric('Extreme WebGL FPS (higher is better)', 'webgl', /fps=([0-9.]+)/);
extremeMetric('Extreme network RPS (higher is better)', 'net', /rps=([0-9.]+)/);
extremeMetric('Extreme network p99.9 (ms, lower is better)', 'net', /p99\.9=([0-9.]+)/);
if (rows.length) {
  out += '| Benchmark | ' + labels.join(' | ') + ' |\n|---|' + labels.map(() => '---').join('|') + '|\n' + rows.join('\n') + '\n\n';
}
const failures = docs.filter(d => d.failure).map(d => `${d.label || d.browser} run ${d.run}: ${d.failure}`);
if (failures.length) out += 'Run failures: ' + failures.join('; ') + '\n';
process.stdout.write(out);
