#!/usr/bin/env node
// bench.mjs - cross-browser benchmark runner (macOS).
//
// Drives Lethe (via --e2e-script) and Google Chrome (via the DevTools
// protocol) through the SAME declarative step list, evaluates the SAME
// metrics JavaScript in both, and samples process RSS at the same points.
// No browser-specific favours: fresh profile, cold launch, sequential.
//
//   node tools/bench/bench.mjs --browser lethe|lethe-noproxy|chrome \
//        [--suite pageload,memory,speedometer,startup] [--runs 3] \
//        [--sites tools/bench/sites.txt] [--out tools/bench/results]
//
// Output: one JSON file per (browser, run). tools/bench/report.mjs turns a
// results directory into docs/BENCHMARKS.md tables.

import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');

const args = Object.fromEntries(process.argv.slice(2).map((a, i, all) => {
  if (!a.startsWith('--')) return [];
  const [k, v] = a.slice(2).split('=');
  return [k, v ?? (all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : 'true')];
}).filter(e => e.length));

const BROWSER = args.browser || 'lethe';
// Variant label for the output (default = browser id) and extra environment
// for the browser process, e.g. --label lethe-nocache --env LETHE_DOH_SHARED_CACHE=0
const LABEL = args.label || BROWSER;
const EXTRA_ENV = Object.fromEntries((args.env || '').split(',').filter(Boolean).map(kv => kv.split('=')));
const EXTRA_ARGS = (args['browser-args'] || '').split(' ').filter(Boolean);
const SUITES = (args.suite || 'startup,pageload,memory,speedometer').split(',');
const RUNS = Number(args.runs || 3);
const OUT = resolve(args.out || join(HERE, 'results'));
const SITES = readFileSync(resolve(args.sites || join(HERE, 'sites.txt')), 'utf8')
  .split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#'));
const LETHE_BIN = args.lethe || join(REPO, 'build', 'lethe.app', 'Contents', 'MacOS', 'lethe');
const CHROME_BIN = args.chrome || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const NAV_TIMEOUT = Number(args['nav-timeout'] || 45000);
const SPEEDOMETER_URL = 'https://browserbench.org/Speedometer3.1/?startAutomatically=true';
const SPEEDOMETER_TIMEOUT = 12 * 60 * 1000;
const JETSTREAM_URL = 'https://browserbench.org/JetStream2.2/';
const JETSTREAM_TIMEOUT = 20 * 60 * 1000;
const MOTIONMARK_URL = 'https://browserbench.org/MotionMark1.3.2/';
const MOTIONMARK_TIMEOUT = 15 * 60 * 1000;
// Blender's Big Buck Bunny (public, stable id), played muted for 20 s.
const YOUTUBE_URL = 'https://www.youtube.com/watch?v=aqz-KE-bpKQ';
const YOUTUBE_PLAY_MS = 20000;

// Identical in every browser: navigation timing + paint + resource bytes.
const METRICS_JS = `(function(){
  var n = performance.getEntriesByType('navigation')[0] || {};
  var rs = performance.getEntriesByType('resource');
  var p = performance.getEntriesByType('paint');
  var bytes = n.transferSize || 0, opaque = 0;
  for (var i = 0; i < rs.length; i++) { bytes += rs[i].transferSize || 0; if (!rs[i].transferSize) opaque++; }
  var fcp = p.filter(function(e){ return e.name === 'first-contentful-paint'; })[0];
  return JSON.stringify({ url: location.href, ttfb: n.responseStart || null,
    dcl: n.domContentLoadedEventEnd || null, load: n.loadEventEnd || null,
    fcp: fcp ? fcp.startTime : null, resources: rs.length, opaqueResources: opaque,
    bytes: bytes, domNodes: document.getElementsByTagName('*').length });
})()`;
const SPEEDOMETER_DONE_JS = `(function(){ var e = document.querySelector('#result-number');
  return e && e.textContent.trim() ? e.textContent.trim() : ''; })()`;
// JetStream preloads its workloads first; the "Start Test" link appears only
// when that is done and start() before it silently does nothing useful.
const JETSTREAM_START_JS = `(function(){ var a = document.querySelector('#status a.button');
  if (a && typeof JetStream !== 'undefined' && JetStream.start) { JetStream.start(); return 'started'; } return ''; })()`;
const JETSTREAM_DONE_JS = `(function(){ var e = document.querySelector('#result-summary .score');
  return e && e.textContent.trim() ? e.textContent.trim() : ''; })()`;
const MOTIONMARK_START_JS = `(function(){ if (typeof benchmarkController !== 'undefined') { benchmarkController.startBenchmark(); return 'started'; } return ''; })()`;
const MOTIONMARK_DONE_JS = `(function(){ var r = document.querySelector('#results'); if (!r) return '';
  var e = r.querySelector('.score'); var t = e && e.textContent.trim(); return t && /[0-9]/.test(t) ? t : ''; })()`;
// YouTube: pick the <video>, mute, play; report decoded/dropped frames.
const YOUTUBE_START_JS = `(function(){ var v = document.querySelector('video'); if (!v) return '';
  v.muted = true; var p = v.play(); if (p && p.catch) p.catch(function(){}); return v.readyState >= 1 ? 'ready' : ''; })()`;
const YOUTUBE_PLAYING_JS = `(function(){ var v = document.querySelector('video'); return v && !v.paused && v.currentTime > 0.5 ? 'playing' : ''; })()`;
const YOUTUBE_STATS_JS = `(function(){ var v = document.querySelector('video'); if (!v) return JSON.stringify({error:'no video'});
  var q = v.getVideoPlaybackQuality ? v.getVideoPlaybackQuality() : {};
  return JSON.stringify({ currentTime: v.currentTime, paused: v.paused, width: v.videoWidth, height: v.videoHeight,
    totalFrames: q.totalVideoFrames || 0, droppedFrames: q.droppedVideoFrames || 0 }); })()`;

// ---------------------------------------------------------------- steps
function buildSteps() {
  const steps = [];
  steps.push({ op: 'mark', name: 'ready' });
  if (SUITES.includes('pageload') || SUITES.includes('memory')) {
    SITES.forEach((url, i) => {
      steps.push(i === 0 ? { op: 'navigate', url, timeout: NAV_TIMEOUT }
                         : { op: 'newtab', url, timeout: NAV_TIMEOUT });
      steps.push({ op: 'sleep', ms: 1500 });
      steps.push({ op: 'eval', js: METRICS_JS, key: `pageload:${url}` });
    });
    if (SUITES.includes('memory')) {
      steps.push({ op: 'sleep', ms: 5000 });
      steps.push({ op: 'mark', name: 'memory:all-tabs' });
      steps.push({ op: 'sleep', ms: 2500 });
    }
  }
  if (SUITES.includes('youtube')) {
    steps.push({ op: 'newtab', url: YOUTUBE_URL, timeout: NAV_TIMEOUT });
    steps.push({ op: 'waitJs', js: YOUTUBE_START_JS, timeout: 30000 });
    steps.push({ op: 'waitJs', js: YOUTUBE_PLAYING_JS, timeout: 30000 });
    steps.push({ op: 'mark', name: 'youtube:start' });
    steps.push({ op: 'sleep', ms: YOUTUBE_PLAY_MS });
    steps.push({ op: 'mark', name: 'youtube:end' });
    steps.push({ op: 'sleep', ms: 1500 });   // keep the process alive while the harness samples
    steps.push({ op: 'eval', js: YOUTUBE_STATS_JS, key: 'youtube:stats' });
  }
  if (SUITES.includes('speedometer')) {
    steps.push({ op: 'newtab', url: SPEEDOMETER_URL, timeout: NAV_TIMEOUT });
    steps.push({ op: 'mark', name: 'speedometer:start' });
    steps.push({ op: 'waitJs', js: SPEEDOMETER_DONE_JS, timeout: SPEEDOMETER_TIMEOUT });
    steps.push({ op: 'mark', name: 'speedometer:end' });
    steps.push({ op: 'sleep', ms: 1500 });   // keep the process alive while the harness samples
    steps.push({ op: 'eval', js: SPEEDOMETER_DONE_JS, key: 'speedometer:score' });
  }
  if (SUITES.includes('jetstream')) {
    steps.push({ op: 'newtab', url: JETSTREAM_URL, timeout: NAV_TIMEOUT });
    steps.push({ op: 'waitJs', js: JETSTREAM_START_JS, timeout: 60000 });
    steps.push({ op: 'mark', name: 'jetstream:start' });
    steps.push({ op: 'waitJs', js: JETSTREAM_DONE_JS, timeout: JETSTREAM_TIMEOUT });
    steps.push({ op: 'mark', name: 'jetstream:end' });
    steps.push({ op: 'sleep', ms: 1500 });   // keep the process alive while the harness samples
    steps.push({ op: 'eval', js: JETSTREAM_DONE_JS, key: 'jetstream:score' });
  }
  if (SUITES.includes('motionmark')) {
    steps.push({ op: 'newtab', url: MOTIONMARK_URL, timeout: NAV_TIMEOUT });
    steps.push({ op: 'waitJs', js: MOTIONMARK_START_JS, timeout: 60000 });
    steps.push({ op: 'mark', name: 'motionmark:start' });
    steps.push({ op: 'waitJs', js: MOTIONMARK_DONE_JS, timeout: MOTIONMARK_TIMEOUT });
    steps.push({ op: 'mark', name: 'motionmark:end' });
    steps.push({ op: 'sleep', ms: 1500 });   // keep the process alive while the harness samples
    steps.push({ op: 'eval', js: MOTIONMARK_DONE_JS, key: 'motionmark:score' });
  }
  steps.push({ op: 'quit' });
  return steps;
}

// ------------------------------------------------------------ processes
// cputime column: [[dd-]hh:]mm:ss.cc  -> seconds
function parseCpuTime(t) {
  let days = 0;
  if (t.includes('-')) { const [d, rest] = t.split('-'); days = Number(d); t = rest; }
  const parts = t.split(':').map(Number);
  let s = 0;
  for (const p of parts) s = s * 60 + p;
  return days * 86400 + s;
}

function psAll() {
  const out = execFileSync('ps', ['-axo', 'pid=,rss=,cputime=,command='], { encoding: 'utf8', maxBuffer: 64 << 20 });
  const rows = [];
  for (const line of out.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/);
    if (m) rows.push({ pid: Number(m[1]), rssKb: Number(m[2]), cpuSec: parseCpuTime(m[3]), cmd: m[4] });
  }
  return rows;
}

// RSS + cumulative CPU seconds of every process attributed to the browser.
function sampleRss(filter) {
  const rows = psAll().filter(filter);
  return { rssMb: rows.reduce((a, r) => a + r.rssKb, 0) / 1024, processes: rows.length,
           cpuSec: +rows.reduce((a, r) => a + r.cpuSec, 0).toFixed(2),
           breakdown: rows.map(r => ({ pid: r.pid, rssMb: +(r.rssKb / 1024).toFixed(1), cpuSec: r.cpuSec, name: r.cmd.split(' ')[0].split('/').pop() })) };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------- Lethe
async function runLethe(steps, { noProxy }) {
  if (!existsSync(LETHE_BIN)) throw new Error(`lethe binary missing: ${LETHE_BIN}`);
  const script = [];
  for (const s of steps) {
    switch (s.op) {
      case 'mark': script.push(`mark ${s.name}`); break;
      case 'navigate': script.push(`load ${s.url}`, `try-wait ${s.timeout}`); break;
      case 'newtab': script.push(`newtab ${s.url}`, `try-wait ${s.timeout}`); break;
      case 'sleep': script.push(`sleep ${s.ms}`); break;
      case 'eval': script.push(`print-js ${s.js.replace(/\s*\n\s*/g, ' ')}`); break;
      case 'waitJs': script.push(`wait-js ${s.timeout} ${s.js.replace(/\s*\n\s*/g, ' ')}`); break;
      case 'quit': script.push('quit'); break;
    }
  }
  const dir = mkdtempSync(join(tmpdir(), 'lethe-bench-'));
  const scriptPath = join(dir, 'bench.lethe');
  writeFileSync(scriptPath, script.join('\n') + '\n');

  const before = new Set(psAll().map(r => r.pid));
  const t0 = performance.now();
  const bin = LETHE_BIN;
  const argv = ['--e2e-script', scriptPath, ...EXTRA_ARGS];
  if (noProxy) argv.push('--no-proxy');
  // Chrome activates itself on launch and so runs every suite as the
  // frontmost app; WebKit throttles timers and suspends requestAnimationFrame
  // for occluded windows. Same footing for Lethe: keep it frontmost too.
  const env = { ...process.env, ...EXTRA_ENV };
  if (env.LETHE_KEEP_FRONT === undefined) env.LETHE_KEEP_FRONT = '1';
  const child = spawn(bin, argv, { stdio: ['ignore', 'pipe', 'pipe'], env });
  const pid = child.pid;
  const isOurs = r => r.pid === pid ||
    (!before.has(r.pid) && /com\.apple\.WebKit\.(WebContent|Networking|GPU)/.test(r.cmd));

  const events = { results: [], marks: [], startupMs: null, exitCode: null, log: [] };
  const evalKeys = steps.filter(s => s.op === 'eval').map(s => s.key);
  let resultIdx = 0;
  let buf = '';
  const onLine = async line => {
    events.log.push(line);
    if (line.startsWith('[e2e] start')) events.startupMs = performance.now() - t0;
    else if (line.startsWith('[e2e] result ')) {
      events.results.push({ key: evalKeys[resultIdx++], value: line.slice(13) });
    } else if (line.startsWith('[e2e] mark ')) {
      const name = line.slice(11).trim();
      const rss = sampleRss(isOurs);
      events.marks.push({ name, tMs: performance.now() - t0, ...rss });
    } else if (line.startsWith('[e2e] timeout ')) {
      events.timeouts = (events.timeouts || 0) + 1;
    } else if (line.startsWith('[e2e] FAIL')) {
      events.failure = line;
    }
  };
  child.stdout.on('data', d => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { onLine(buf.slice(0, i)); buf = buf.slice(i + 1); } });
  child.stderr.on('data', d => events.log.push(String(d).trimEnd()));
  await new Promise(res => child.on('exit', code => { events.exitCode = code; res(); }));
  rmSync(dir, { recursive: true, force: true });
  return events;
}

// ------------------------------------------------------------- Chrome
class Cdp {
  constructor(url) { this.ws = new WebSocket(url); this.id = 0; this.pending = new Map(); this.listeners = []; }
  open() { return new Promise((res, rej) => { this.ws.onopen = res; this.ws.onerror = e => rej(new Error('ws error')); this.ws.onmessage = m => this.onMessage(m); }); }
  onMessage(m) {
    const msg = JSON.parse(m.data);
    if (msg.id && this.pending.has(msg.id)) { const { res, rej } = this.pending.get(msg.id); this.pending.delete(msg.id); msg.error ? rej(new Error(JSON.stringify(msg.error))) : res(msg.result); }
    else if (msg.method) for (const l of this.listeners) l(msg);
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((res, rej) => { this.pending.set(id, { res, rej }); this.ws.send(JSON.stringify({ id, method, params, sessionId })); });
  }
  waitFor(method, sessionId, timeoutMs) {
    return new Promise((res, rej) => {
      const t = setTimeout(() => { this.listeners = this.listeners.filter(x => x !== l); rej(new Error(`timeout waiting ${method}`)); }, timeoutMs);
      const l = msg => { if (msg.method === method && (!sessionId || msg.sessionId === sessionId)) { clearTimeout(t); this.listeners = this.listeners.filter(x => x !== l); res(msg.params); } };
      this.listeners.push(l);
    });
  }
  close() { this.ws.close(); }
}

async function runChrome(steps) {
  if (!existsSync(CHROME_BIN)) throw new Error(`chrome binary missing: ${CHROME_BIN}`);
  const profile = mkdtempSync(join(tmpdir(), 'chrome-bench-'));
  const t0 = performance.now();
  const child = spawn(CHROME_BIN, [
    `--user-data-dir=${profile}`, '--remote-debugging-port=0', '--no-first-run',
    '--no-default-browser-check', '--window-size=1280,900', ...EXTRA_ARGS, 'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...EXTRA_ENV } });
  const events = { results: [], marks: [], startupMs: null, exitCode: null, log: [] };
  child.stderr.on('data', d => events.log.push(String(d).trimEnd()));
  child.stdout.on('data', d => events.log.push(String(d).trimEnd()));
  const isOurs = r => r.pid === child.pid || r.cmd.includes(profile);

  const portFile = join(profile, 'DevToolsActivePort');
  while (!existsSync(portFile)) { await sleep(20); if (performance.now() - t0 > 30000) throw new Error('chrome did not expose DevTools'); }
  const [port, path] = readFileSync(portFile, 'utf8').trim().split('\n');
  const cdp = new Cdp(`ws://127.0.0.1:${port}${path}`);
  await cdp.open();
  let { targetInfos } = await cdp.send('Target.getTargets');
  let page = targetInfos.find(t => t.type === 'page');
  while (!page) { await sleep(20); ({ targetInfos } = await cdp.send('Target.getTargets')); page = targetInfos.find(t => t.type === 'page'); }
  let session = (await cdp.send('Target.attachToTarget', { targetId: page.targetId, flatten: true })).sessionId;
  await cdp.send('Page.enable', {}, session);
  await cdp.send('Runtime.enable', {}, session);

  const navigate = async (url, timeout) => {
    const loaded = cdp.waitFor('Page.loadEventFired', session, timeout);
    await cdp.send('Page.navigate', { url }, session);
    try { await loaded; }
    catch (e) {
      // Same semantics as Lethe's try-wait: stop, record, carry on.
      events.timeouts = (events.timeouts || 0) + 1;
      events.log.push(`[bench] timeout: load event not fired within ${timeout} ms for ${url}`);
      await cdp.send('Page.stopLoading', {}, session).catch(() => {});
    }
  };
  const evaluate = async (js, userGesture = false) => {
    const r = await cdp.send('Runtime.evaluate', { expression: js, returnByValue: true, userGesture }, session);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
    const v = r.result.value;
    return v === undefined || v === null ? '' : String(v);
  };

  try {
    for (const s of steps) {
      switch (s.op) {
        case 'mark': {
          if (s.name === 'ready') events.startupMs = performance.now() - t0;
          events.marks.push({ name: s.name, tMs: performance.now() - t0, ...sampleRss(isOurs) });
          break;
        }
        case 'navigate': await navigate(s.url, s.timeout); break;
        case 'newtab': {
          const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
          session = (await cdp.send('Target.attachToTarget', { targetId, flatten: true })).sessionId;
          await cdp.send('Page.enable', {}, session);
          await cdp.send('Runtime.enable', {}, session);
          await navigate(s.url, s.timeout);
          break;
        }
        case 'sleep': await sleep(s.ms); break;
        case 'eval': events.results.push({ key: s.key, value: await evaluate(s.js) }); break;
        case 'waitJs': {
          const deadline = performance.now() + s.timeout;
          for (;;) {
            const v = await evaluate(s.js, true).catch(() => '');
            if (v && v !== 'false' && v !== '0') break;
            if (performance.now() > deadline) throw new Error(`waitJs timeout: ${s.js.slice(0, 60)}`);
            await sleep(500);
          }
          break;
        }
        case 'quit': break;
      }
    }
    events.exitCode = 0;
  } catch (e) {
    events.failure = String(e.message || e);
    events.exitCode = 1;
  } finally {
    try { await cdp.send('Browser.close'); } catch {}
    cdp.close();
    await Promise.race([new Promise(r => child.on('exit', r)), sleep(5000)]);
    try { child.kill('SIGKILL'); } catch {}
    rmSync(profile, { recursive: true, force: true });
  }
  return events;
}

// --------------------------------------------------------------- main
function versionOf(browser) {
  try {
    if (browser.startsWith('lethe')) return execFileSync(LETHE_BIN, ['--version'], { encoding: 'utf8' }).trim();
    return execFileSync(CHROME_BIN, ['--version'], { encoding: 'utf8' }).trim();
  } catch { return 'unknown'; }
}

function hostInfo() {
  const sw = execFileSync('sw_vers', ['-productVersion'], { encoding: 'utf8' }).trim();
  const cpu = execFileSync('sysctl', ['-n', 'machdep.cpu.brand_string'], { encoding: 'utf8' }).trim();
  const mem = Number(execFileSync('sysctl', ['-n', 'hw.memsize'], { encoding: 'utf8' })) / 2 ** 30;
  return { os: `macOS ${sw}`, cpu, memoryGb: Math.round(mem) };
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const steps = buildSteps();
  const version = versionOf(BROWSER);
  console.log(`[bench] ${LABEL} = ${BROWSER} (${version}) suites=${SUITES.join(',')} runs=${RUNS} sites=${SITES.length}` +
    `${Object.keys(EXTRA_ENV).length ? ' env=' + JSON.stringify(EXTRA_ENV) : ''}${EXTRA_ARGS.length ? ' args=' + EXTRA_ARGS.join(' ') : ''}`);
  for (let run = 1; run <= RUNS; run++) {
    const started = new Date();
    console.log(`[bench] run ${run}/${RUNS} ...`);
    const ev = BROWSER === 'chrome' ? await runChrome(steps)
             : await runLethe(steps, { noProxy: BROWSER === 'lethe-noproxy' });
    const doc = {
      browser: BROWSER, label: LABEL, env: EXTRA_ENV, browserArgs: EXTRA_ARGS, version, run, startedAt: started.toISOString(), host: hostInfo(),
      suites: SUITES, sites: SITES, startupMs: ev.startupMs, exitCode: ev.exitCode, failure: ev.failure || null, timeouts: ev.timeouts || 0,
      pageload: ev.results.filter(r => r.key?.startsWith('pageload:')).map(r => { try { return JSON.parse(r.value); } catch { return { url: r.key.slice(9), error: r.value }; } }),
      speedometer: ev.results.find(r => r.key === 'speedometer:score')?.value ?? null,
      jetstream: ev.results.find(r => r.key === 'jetstream:score')?.value ?? null,
      motionmark: ev.results.find(r => r.key === 'motionmark:score')?.value ?? null,
      youtube: (() => { const r = ev.results.find(r => r.key === 'youtube:stats'); if (!r) return null; try { return JSON.parse(r.value); } catch { return { error: r.value }; } })(),
      memory: ev.marks,
    };
    if (ev.failure) doc.log = ev.log.slice(-40);
    const file = join(OUT, `${started.toISOString().replace(/[:.]/g, '-')}-${LABEL}-run${run}.json`);
    writeFileSync(file, JSON.stringify(doc, null, 2));
    const mem = doc.memory.find(m => m.name === 'memory:all-tabs');
    console.log(`[bench]   startup=${doc.startupMs?.toFixed(0)}ms  loads=${doc.pageload.length}/${SITES.length}` +
      `  rss(all tabs)=${mem ? mem.rssMb.toFixed(0) + 'MB/' + mem.processes + 'proc' : 'n/a'}` +
      `  cpu=${mem ? mem.cpuSec + 's' : 'n/a'}  timeouts=${doc.timeouts}  speedometer=${doc.speedometer ?? 'n/a'}` +
      `  jetstream=${doc.jetstream ?? 'n/a'}  motionmark=${doc.motionmark ?? 'n/a'}` +
      `  youtube=${doc.youtube ? (doc.youtube.droppedFrames + '/' + doc.youtube.totalFrames + ' dropped @' + doc.youtube.height + 'p') : 'n/a'}` +
      `  exit=${doc.exitCode}${doc.failure ? '  FAIL: ' + doc.failure : ''}`);
    console.log(`[bench]   -> ${file}`);
  }
}

main().catch(e => { console.error('[bench] fatal:', e); process.exit(1); });
