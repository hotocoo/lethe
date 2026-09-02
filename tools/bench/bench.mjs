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
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

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
const LETHE_CEF_BIN = args['lethe-cef'] || join(REPO, 'build-cef', 'lethe-cef.app', 'Contents', 'MacOS', 'lethe-cef');
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
const YOUTUBE_4K_URL = 'https://www.youtube.com/watch?v=Ba5_jnu_6Jo';  // "Costa Rica in 4K" public 4K HDR sample (60fps, no sign-in)
const YOUTUBE_PLAY_MS = 20000;
const YOUTUBE_4K_PLAY_MS = 30000;   // longer so the player actually reaches 4K
// Stress test: 100,000 DOM nodes + rotating WebGL quad + 20ms JS work per
// frame, all on a same-origin file:// page so the WebView treats it as
// first-party. The page self-reports fps and frame count; the harness
// reads the stats overlay at the end. The page is written to a temp
// file once per run so a fresh copy is used for each measurement.
function writeStressPage() {
  const path = join(mkdtempSync(join(tmpdir(), 'lethe-stress-')), 'stress.html');
  writeFileSync(path, `<!doctype html><meta charset="utf-8">
<title>Lethe stress</title>
<style>body{margin:0;background:#000;color:#fff;font:14px monospace}</style>
<canvas id="gl" width="1280" height="720"></canvas>
<div id="nodes"></div>
<div id="stats" style="position:fixed;top:8px;right:8px;background:rgba(0,0,0,0.6);padding:6px 10px;border-radius:6px"></div>
<script>
// 100k DOM nodes (one row per 50 nodes)
const nd = document.getElementById('nodes');
for (let i = 0; i < 2000; i++) {
  const row = document.createElement('div');
  let inner = '';
  for (let j = 0; j < 50; j++) inner += '<span>' + (i*50+j) + '</span> ';
  row.innerHTML = inner;
  nd.appendChild(row);
}
// WebGL: rotating quad
const gl = document.getElementById('gl').getContext('webgl');
let prog;
if (gl) {
  const vs = gl.createShader(gl.VERTEX_SHADER);
  gl.shaderSource(vs, 'attribute vec2 p;uniform float t;varying float v;void main(){v=t;gl_Position=vec2(p.x*cos(t)-p.y*sin(t),p.x*sin(t)+p.y*cos(t))*0.6,0,1);}');
  gl.compileShader(vs);
  const fs = gl.createShader(gl.FRAGMENT_SHADER);
  gl.shaderSource(fs, 'precision mediump float;varying float v;void main(){gl_FragColor=vec4(0.5+0.5*sin(v),0.3+0.5*cos(v*0.7),0.6+0.4*sin(v*1.3),1);}');
  gl.compileShader(fs);
  prog = gl.createProgram(); gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog);
  const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.5,-0.5,0.5,-0.5,-0.5,0.5,0.5,-0.5,0.5,0.5,-0.5,0.5]), gl.STATIC_DRAW);
}
let frames = 0, t0 = performance.now(), lastJ = 0;
function tick(t) {
  frames++;
  if (gl) {
    gl.viewport(0, 0, 1280, 720); gl.clearColor(0, 0, 0, 1); gl.clear(gl.COLOR_BUFFER_BIT);
    gl.useProgram(prog);
    const loc = gl.getUniformLocation(prog, 't'); gl.uniform1f(loc, t / 1000);
    const pl = gl.getAttribLocation(prog, 'p'); gl.enableVertexAttribArray(pl);
    gl.vertexAttribPointer(pl, 2, gl.FLOAT, false, 0, 0);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
  }
  let x = 0; for (let i = 0; i < 1e6; i++) x += Math.sqrt(i) * Math.sin(i * 0.001);
  lastJ = x;
  if (frames % 30 === 0) {
    const e = performance.now() - t0;
    document.getElementById('stats').textContent =
      'fps=' + (frames * 1000 / e).toFixed(1) + ' frames=' + frames + ' dom=100k j=' + lastJ.toFixed(2);
  }
  requestAnimationFrame(tick);
}
requestAnimationFrame(tick);
</script>
`);
  return path;
}
const STRESS_DURATION_MS = 60000;

// ---------------------------------------------------------------- extreme
// "Extreme" is not "hard": these workloads are an order of magnitude past
// the 100k-node stress page and are designed to saturate the renderer, the
// JS engine, the GPU, and (for extreme-net) the engine's network stack and
// Lethe's policy proxy. Each sub-test is a self-contained same-origin page
// that self-reports its own metric into #stats; the harness reads it at the
// end. Identical page + identical JS in both browsers.

// 1) extreme-dom: 500,000 live DOM nodes (5x the old stress), a forced
//    layout-thrash pass, then 600 frames of rAF with the whole tree present.
//    Metric: node count, build ms, thrash ms, sustained FPS.
function writeExtremeDomPage() {
  const path = join(mkdtempSync(join(tmpdir(), 'lethe-xdom-')), 'xdom.html');
  writeFileSync(path, `<!doctype html><meta charset="utf-8">
<title>Lethe extreme DOM</title>
<style>body{margin:0;background:#000;color:#fff;font:11px monospace}
.row{display:flex}.c{padding:0 3px;border-right:1px solid #1a1a1a}.a{background:#0a0a0a}
#stats{position:fixed;top:6px;right:6px;background:rgba(0,0,0,.7);padding:5px 9px;border-radius:5px;z-index:9}</style>
<div id="n"></div><div id="stats">building…</div>
<script>
var nd=document.getElementById('n'),st=document.getElementById('stats');
var t0=performance.now(),frag=document.createDocumentFragment();
for(var i=0;i<2500;i++){var r=document.createElement('div');r.className='row'+(i&1?' a':'');
var h='';for(var j=0;j<100;j++)h+='<span class="c">'+(i*100+j)+'</span>';
r.innerHTML=h;frag.appendChild(r);}
nd.appendChild(frag);
var build=performance.now()-t0;
// forced layout thrash: 40 alternating read/write passes
var t1=performance.now();
for(var k=0;k<40;k++){var h2=nd.offsetHeight;nd.style.marginTop=(k&1)+'px';}
var thrash=performance.now()-t1;
var count=document.getElementsByTagName('*').length;
st.textContent='dom='+count+' build='+build.toFixed(0)+'ms thrash='+thrash.toFixed(0)+'ms fps=…';
var frames=0,ft=performance.now();
function tick(){frames++;
 if(frames>=600){var fps=frames*1000/(performance.now()-ft);
  st.textContent='dom='+count+' build='+build.toFixed(0)+'ms thrash='+thrash.toFixed(0)+'ms fps='+fps.toFixed(1);
  return;}
 requestAnimationFrame(tick);}
requestAnimationFrame(tick);
</script>`);
  return path;
}

// 2) extreme-js: CPU-saturating compute. A fixed 8-second budget of the
//    hardest single-threaded work a page can do: a 512x512 matrix multiply
//    in a Float64Array, a SHA-256 of 16 MiB via WebCrypto, and a deep
//    recursive tree. Metric: total ops completed in the window + wall ms.
function writeExtremeJsPage() {
  const path = join(mkdtempSync(join(tmpdir(), 'lethe-xjs-')), 'xjs.html');
  writeFileSync(path, `<!doctype html><meta charset="utf-8">
<title>Lethe extreme JS</title>
<style>body{margin:0;background:#000;color:#fff;font:12px monospace}
#stats{position:fixed;top:6px;right:6px;background:rgba(0,0,0,.7);padding:5px 9px;border-radius:5px}</style>
<div id="stats">running…</div>
<script>
var st=document.getElementById('stats');
var N=512, A=new Float64Array(N*N), B=new Float64Array(N*N), C=new Float64Array(N*N);
for(var i=0;i<N*N;i++){A[i]=Math.random();B[i]=Math.random();}
var matMul=0, cryptoOps=0, recOps=0, t0=performance.now(), deadline=t0+8000;
function matMulOnce(){C.fill(0);
 for(var i=0;i<N;i++)for(var k=0;k<N;k++){var a=A[i*N+k];if(!a)continue;
  for(var j=0;j<N;j++)C[i*N+j]+=a*B[k*N+j];} matMul++;}
function trib(n){if(n<=1)return 1;if(n===2)return 2;return trib(n-1)+trib(n-2)+trib(n-3);}
async function cryptoOnce(){
 var buf=new ArrayBuffer(16*1024*1024);var dv=new DataView(buf);
 for(var i=0;i<dv.byteLength;i+=4)dv.setUint32(i,i*2654435761>>>0,true);
 var h=await globalThis.crypto.subtle.digest('SHA-256',buf);cryptoOps++;return h;}
async function run(){
 var last=performance.now();
 while(performance.now()<deadline){
  var now=performance.now();
  if(now-last>40){ // chunk so the page can still paint
   matMulOnce(); last=now;
   st.textContent='js matMul='+matMul+' crypto='+cryptoOps+' rec='+recOps+' t='+(now-t0).toFixed(0)+'ms';
   await new Promise(r=>setTimeout(r,0));
  } else { matMulOnce(); }
 }
 // final crypto + recursion burst (bounded depth so it cannot hang)
 var h=await cryptoOnce();
 var r=trib(30); recOps++;
 st.textContent='js matMul='+matMul+' crypto='+cryptoOps+' rec='+recOps+' t='+(performance.now()-t0).toFixed(0)+'ms ok='+(r>0&&h.byteLength===32);
}
run();
</script>`);
  return path;
}

// 3) extreme-webgl: GPU-bound. 4096 textured quads (4x4 grid of 32x32) with
//    per-quad transforms and a fragment shader doing per-pixel work, at
//    1920x1080. Metric: sustained FPS over 600 frames.
function writeExtremeWebglPage() {
  const path = join(mkdtempSync(join(tmpdir(), 'lethe-xgl-')), 'xgl.html');
  writeFileSync(path, `<!doctype html><meta charset="utf-8">
<title>Lethe extreme WebGL</title>
<style>body{margin:0;background:#000}canvas{display:block}
#stats{position:fixed;top:6px;right:6px;background:rgba(0,0,0,.7);color:#fff;padding:5px 9px;border-radius:5px;font:12px monospace}</style>
<canvas id="gl" width="960" height="540"></canvas><div id="stats">init…</div>
<script>
var gl=document.getElementById('gl').getContext('webgl',{antialias:false});
var st=document.getElementById('stats');
var vs=gl.createShader(gl.VERTEX_SHADER);
gl.shaderSource(vs,'attribute vec2 p;attribute vec2 uv;uniform mat2 rot;uniform vec2 off;varying vec2 vuv;void main(){vuv=uv;vec2 q=rot*p;gl_Position=vec4(q+off,0.,1.);}');
gl.compileShader(vs);
var fs=gl.createShader(gl.FRAGMENT_SHADER);
gl.shaderSource(fs,'precision mediump float;varying vec2 vuv;uniform float t;void main(){float v=sin(vuv.x*40.+t)*cos(vuv.y*40.-t*1.3);gl_FragColor=vec4(.5+.5*v,.3+.4*cos(v*3.+t),.6+.4*sin(v*5.-t),1.);}');
gl.compileShader(fs);
var prog=gl.createProgram();gl.attachShader(prog,vs);gl.attachShader(prog,fs);gl.linkProgram(prog);gl.useProgram(prog);
// 32x32 texture
var tw=32,th=32,tx=gl.createTexture();gl.bindTexture(gl.TEXTURE_2D,tx);
var px=new Uint8Array(tw*th*4);for(var i=0;i<tw*th;i++){px[i*4]=i*8&255;px[i*4+1]=(i*5)&255;px[i*4+2]=(i*3)&255;px[i*4+3]=255;}
gl.texImage2D(gl.TEXTURE_2D,0,gl.RGBA,tw,th,0,gl.RGBA,gl.UNSIGNED_BYTE,px);
gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MIN_FILTER,gl.LINEAR);
var buf=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,buf);
var quad=new Float32Array([-1,-1,0,0, 1,-1,1,0, -1,1,0,1, 1,1,1,1]);
gl.bufferData(gl.ARRAY_BUFFER,quad,gl.STATIC_DRAW);
var lp=gl.getAttribLocation(prog,'p'),lu=gl.getAttribLocation(prog,'uv');
gl.enableVertexAttribArray(lp);gl.vertexAttribPointer(lp,2,gl.FLOAT,false,8,0);
gl.enableVertexAttribArray(lu);gl.vertexAttribPointer(lu,2,gl.FLOAT,false,8,4);
var lr=gl.getUniformLocation(prog,'rot'),lo=gl.getUniformLocation(prog,'off'),lt=gl.getUniformLocation(prog,'t');
gl.activeTexture(gl.TEXTURE0);gl.bindTexture(gl.TEXTURE_2D,tx);
var GRID=16, QUADS=GRID*GRID; // 256 quads
var frames=0,t0=performance.now();
function tick(t){frames++;var tt=t/1000;
 gl.viewport(0,0,960,540);gl.clearColor(0,0,0,1);gl.clear(gl.COLOR_BUFFER_BIT);
gl.uniform1f(lt,tt);
 for(var i=0;i<QUADS;i++){
  var gx=i%GRID,gy=(i/GRID)|0;
  var a=tt*0.5+gx*0.3+gy*0.2,ca=Math.cos(a),sa=Math.sin(a);
  gl.uniformMatrix2fv(lr,false,[ca,-sa,sa,ca]);
  gl.uniform2f(lo,(gx-GRID/2)*0.155,(gy-GRID/2)*0.155);
  gl.drawArrays(gl.TRIANGLE_STRIP,0,4);
 }
 if(frames%30===0){var e=performance.now()-t0;st.textContent='webgl quads='+QUADS+' fps='+(frames*1000/e).toFixed(1)+' frames='+frames;}
 if(frames<600)requestAnimationFrame(tick);
 else{var e2=performance.now()-t0;st.textContent='webgl quads='+QUADS+' fps='+(frames*1000/e2).toFixed(1)+' frames='+frames;}}
requestAnimationFrame(tick);
</script>`);
  return path;
}

// 4) extreme-net: N parallel HTTP requests through the engine's network
//    stack (and, on Lethe, the policy proxy). The harness serves N small
//    files from a local origin; the page fetches them all concurrently and
//    reports completion time + bytes. This is the proxy's real-world torture.
const EXTREME_NET_COUNT = 300;
const EXTREME_NET_BYTES = 1024; // per file
function extremeNetPageUrl(base) {
  return base + '/xnet.html';
}
function writeExtremeNetPage(count, bytes) {
  const dir = mkdtempSync(join(tmpdir(), 'lethe-xnet-'));
  // The page: fire all requests concurrently, report when done.
  writeFileSync(join(dir, 'xnet.html'), `<!doctype html><meta charset="utf-8">
<title>Lethe extreme NET</title>
<style>body{margin:0;background:#000;color:#fff;font:12px monospace}
#stats{position:fixed;top:6px;right:6px;background:rgba(0,0,0,.7);padding:5px 9px;border-radius:5px}</style>
<div id="stats">fetching ${count}…</div>
<script>
var st=document.getElementById('stats');
var N=${count}, t0=performance.now(), done=0, bytes=0;
var ps=[];
for(var i=0;i<N;i++){
 ps.push(fetch('/f'+i+'.bin',{cache:'no-store'}).then(function(r){
  return r.arrayBuffer().then(function(b){bytes+=b.byteLength;done++;});
 }).catch(function(){done++;}));
}
Promise.all(ps).then(function(){
 var ms=performance.now()-t0;
 st.textContent='net n='+N+' done='+done+' bytes='+bytes+' t='+ms.toFixed(0)+'ms rps='+((N*1000)/ms).toFixed(0);
});
</script>`);
  // The N payload files.
  const payload = Buffer.alloc(bytes, 7);
  for (let i = 0; i < count; i++) writeFileSync(join(dir, `f${i}.bin`), payload);
  return dir;
}
const EXTREME_NET_DURATION_MS = 30000;

// A single local origin that serves every extreme page. Both browsers
// navigate to http://127.0.0.1:<port>/<page>.html so the workload is
// byte-identical; on Lethe every request additionally rides the policy
// proxy (loopback is allow-listed), which is exactly the real-world path.
// The server is started lazily when an extreme suite runs and closed at
// the end of the run.
let extremeServer = null;
let extremeDir = null;
async function ensureExtremeServer() {
  if (extremeServer) return extremeServer.base;
  extremeDir = mkdtempSync(join(tmpdir(), 'lethe-extreme-'));
  // Write the three compute pages + the net page + its payloads.
  const domHtml = readFileSync(writeExtremeDomPage(), 'utf8');
  const jsHtml = readFileSync(writeExtremeJsPage(), 'utf8');
  const glHtml = readFileSync(writeExtremeWebglPage(), 'utf8');
  writeFileSync(join(extremeDir, 'xdom.html'), domHtml);
  writeFileSync(join(extremeDir, 'xjs.html'), jsHtml);
  writeFileSync(join(extremeDir, 'xgl.html'), glHtml);
  // extreme-net page + payloads (same origin)
  const netDir = writeExtremeNetPage(EXTREME_NET_COUNT, EXTREME_NET_BYTES);
  for (const f of readdirSync(netDir)) {
    writeFileSync(join(extremeDir, f), readFileSync(join(netDir, f)));
  }
  rmSync(netDir, { recursive: true, force: true });
  const server = http.createServer((req, res) => {
    const url = req.url.split('?')[0];
    const file = join(extremeDir, url === '/' ? 'xdom.html' : url);
    if (!existsSync(file) || !file.startsWith(extremeDir)) {
      res.writeHead(404); res.end('nf'); return;
    }
    const data = readFileSync(file);
    const isBin = file.endsWith('.bin');
    res.writeHead(200, {
      'Content-Type': isBin ? 'application/octet-stream' : 'text/html; charset=utf-8',
      'Content-Length': data.length,
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  extremeServer = { server, base: `http://127.0.0.1:${port}`, port };
  return extremeServer.base;
}
function closeExtremeServer() {
  if (extremeServer) {
    try { extremeServer.server.close(); } catch {}
    extremeServer = null;
  }
  if (extremeDir) {
    try { rmSync(extremeDir, { recursive: true, force: true }); } catch {}
    extremeDir = null;
  }
}

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
function buildSteps(extremeBase) {
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
  if (SUITES.includes('youtube4k')) {
    // 4K HDR YouTube torture. The player is asked for the highest available
    // rendition; on a 4K-capable machine WebKit negotiates 3840x2160 @ 60fps.
    // The bench reports decoded vs dropped frames at the end.
    steps.push({ op: 'newtab', url: YOUTUBE_4K_URL, timeout: 60000 });
    steps.push({ op: 'waitJs', js: YOUTUBE_START_JS, timeout: 30000 });
    steps.push({ op: 'waitJs', js: YOUTUBE_PLAYING_JS, timeout: 30000 });
    steps.push({ op: 'mark', name: 'youtube4k:start' });
    steps.push({ op: 'sleep', ms: YOUTUBE_4K_PLAY_MS });
    steps.push({ op: 'mark', name: 'youtube4k:end' });
    steps.push({ op: 'sleep', ms: 1500 });
    steps.push({ op: 'eval', js: YOUTUBE_STATS_JS, key: 'youtube4k:stats' });
  }
  if (SUITES.includes('stress')) {
    // In-page torture: 100k DOM nodes, rotating WebGL quad, 20ms JS work
    // per frame. On Lethe, the e2e "stress" command renders the page
    // directly via the internal page handler (no policy gate, no
    // network). On Chrome, the bench serves a same-origin file://
    // page so the same JS runs. The page self-reports its FPS; the
    // bench reads the stats overlay at the end.
    if (BROWSER.startsWith('lethe')) {
      steps.push({ op: 'newtab', url: 'about:blank', timeout: 5000 });
      steps.push({ op: 'stress' });
    } else {
      const stressPath = writeStressPage();
      const stressUrl = 'file://' + stressPath;
      steps.push({ op: 'newtab', url: stressUrl, timeout: 30000 });
    }
    steps.push({ op: 'sleep', ms: 5000 });   // warm up
    steps.push({ op: 'mark', name: 'stress:start' });
    steps.push({ op: 'sleep', ms: STRESS_DURATION_MS });
    steps.push({ op: 'mark', name: 'stress:end' });
    steps.push({ op: 'sleep', ms: 1000 });
    steps.push({ op: 'eval', js: 'document.getElementById("stats").textContent',
                 key: 'stress:stats' });
  }
  if (SUITES.includes('extreme-net') && extremeBase) {
    // Focused network torture: N rounds of 300 concurrent fetches so the
    // median is stable. Each round is a fresh tab on the shared origin.
    steps.push({ op: 'sleep', ms: 1000 });
    for (let round = 0; round < 3; round++) {
      steps.push({ op: 'newtab', url: extremeBase + '/xnet.html', timeout: 30000 });
      steps.push({ op: 'waitJs', js: 'document.getElementById("stats").textContent.indexOf("rps=")>=0', timeout: EXTREME_NET_DURATION_MS });
      steps.push({ op: 'sleep', ms: 300 });
      steps.push({ op: 'eval', js: 'document.getElementById("stats").textContent', key: `extreme:net${round}` });
    }
  }
  if (SUITES.includes('extreme') && extremeBase) {
    // Warm up: ensure a live tab exists before the heavy pages land. The
    // initial window's new-tab page is fine; we just need the run loop and
    // WebContent process settled so the first heavy navigation is clean.
    steps.push({ op: 'sleep', ms: 1500 });
    // Four extreme sub-tests, each a fresh tab on the shared local origin.
    // (a) DOM: 500k nodes + thrash + 600 rAF frames (~20s budget)
    steps.push({ op: 'newtab', url: extremeBase + '/xdom.html', timeout: 30000 });
    steps.push({ op: 'sleep', ms: 20000 });
    steps.push({ op: 'eval', js: '(function(){var e=document.getElementById("stats");return e?e.textContent:"LOST";})()', key: 'extreme:dom' });
    steps.push({ op: 'mark', name: 'extreme:mem-dom' });
    // (b) JS: 8s of CPU-saturating compute
    steps.push({ op: 'newtab', url: extremeBase + '/xjs.html', timeout: 30000 });
    steps.push({ op: 'sleep', ms: 11000 });
    steps.push({ op: 'eval', js: '(function(){var e=document.getElementById("stats");return e?e.textContent:"LOST";})()', key: 'extreme:js' });
    steps.push({ op: 'mark', name: 'extreme:mem-js' });
    // (c) WebGL: 4096 textured quads, 600 frames (~20s budget)
    steps.push({ op: 'newtab', url: extremeBase + '/xgl.html', timeout: 30000 });
    steps.push({ op: 'sleep', ms: 20000 });
    steps.push({ op: 'eval', js: '(function(){var e=document.getElementById("stats");return e?e.textContent:"LOST";})()', key: 'extreme:webgl' });
    steps.push({ op: 'mark', name: 'extreme:mem-webgl' });
    // (d) NET: 300 concurrent fetches through the engine's network stack
    //     (and Lethe's policy proxy). The page self-reports when done; we
    //     poll until it does, up to EXTREME_NET_DURATION_MS.
    steps.push({ op: 'newtab', url: extremeBase + '/xnet.html', timeout: 30000 });
    steps.push({ op: 'waitJs', js: 'document.getElementById("stats").textContent.indexOf("rps=")>=0', timeout: EXTREME_NET_DURATION_MS });
    steps.push({ op: 'sleep', ms: 500 });
    steps.push({ op: 'eval', js: 'document.getElementById("stats").textContent', key: 'extreme:net' });
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
async function runLethe(steps, { noProxy, binOverride }) {
  const bin = binOverride || LETHE_BIN;
  if (!existsSync(bin)) throw new Error(`lethe binary missing: ${bin}`);
  const script = [];
  for (const s of steps) {
    switch (s.op) {
      case 'mark': script.push(`mark ${s.name}`); break;
      case 'navigate': script.push(`load ${s.url}`, `try-wait ${s.timeout}`); break;
      case 'newtab': script.push(`newtab ${s.url}`, `try-wait ${s.timeout}`); break;
      case 'sleep': script.push(`sleep ${s.ms}`); break;
      case 'eval': script.push(`print-js ${s.js.replace(/\s*\n\s*/g, ' ')}`); break;
      case 'waitJs': script.push(`wait-js ${s.timeout} ${s.js.replace(/\s*\n\s*/g, ' ')}`); break;
      case 'stress': script.push('stress'); break;
      case 'quit': script.push('quit'); break;
    }
  }
  const dir = mkdtempSync(join(tmpdir(), 'lethe-bench-'));
  const scriptPath = join(dir, 'bench.lethe');
  writeFileSync(scriptPath, script.join('\n') + '\n');

  const before = new Set(psAll().map(r => r.pid));
  const t0 = performance.now();
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
    if (browser === 'lethe-cef') return execFileSync(LETHE_CEF_BIN, ['--version'], { encoding: 'utf8' }).trim();
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
  let extremeBase = null;
  if (SUITES.includes('extreme') || SUITES.includes('extreme-net')) {
    extremeBase = await ensureExtremeServer();
    console.log(`[bench] extreme server on ${extremeBase} (${EXTREME_NET_COUNT} net payloads)`);
  }
  const steps = buildSteps(extremeBase);
  const version = versionOf(BROWSER);
  console.log(`[bench] ${LABEL} = ${BROWSER} (${version}) suites=${SUITES.join(',')} runs=${RUNS} sites=${SITES.length}` +
    `${Object.keys(EXTRA_ENV).length ? ' env=' + JSON.stringify(EXTRA_ENV) : ''}${EXTRA_ARGS.length ? ' args=' + EXTRA_ARGS.join(' ') : ''}`);
  for (let run = 1; run <= RUNS; run++) {
    const started = new Date();
    console.log(`[bench] run ${run}/${RUNS} ...`);
    const ev = BROWSER === 'chrome' ? await runChrome(steps)
             : BROWSER === 'lethe-cef' ? await runLethe(steps, { noProxy: false, binOverride: LETHE_CEF_BIN })
             : await runLethe(steps, { noProxy: BROWSER === 'lethe-noproxy' });
    const doc = {
      browser: BROWSER, label: LABEL, env: EXTRA_ENV, browserArgs: EXTRA_ARGS, version, run, startedAt: started.toISOString(), host: hostInfo(),
      suites: SUITES, sites: SITES, startupMs: ev.startupMs, exitCode: ev.exitCode, failure: ev.failure || null, timeouts: ev.timeouts || 0,
      pageload: ev.results.filter(r => r.key?.startsWith('pageload:')).map(r => { try { return JSON.parse(r.value); } catch { return { url: r.key.slice(9), error: r.value }; } }),
      speedometer: ev.results.find(r => r.key === 'speedometer:score')?.value ?? null,
      jetstream: ev.results.find(r => r.key === 'jetstream:score')?.value ?? null,
      motionmark: ev.results.find(r => r.key === 'motionmark:score')?.value ?? null,
      youtube: (() => { const r = ev.results.find(r => r.key === 'youtube:stats'); if (!r) return null; try { return JSON.parse(r.value); } catch { return { error: r.value }; } })(),
      youtube4k: (() => { const r = ev.results.find(r => r.key === 'youtube4k:stats'); if (!r) return null; try { return JSON.parse(r.value); } catch { return { error: r.value }; } })(),
      stress: (() => { const r = ev.results.find(r => r.key === 'stress:stats'); if (!r) return null; return r.value; })(),
      extreme: {
        dom:   ev.results.find(r => r.key === 'extreme:dom')?.value ?? null,
        js:    ev.results.find(r => r.key === 'extreme:js')?.value ?? null,
        webgl: ev.results.find(r => r.key === 'extreme:webgl')?.value ?? null,
        net:   ev.results.find(r => r.key === 'extreme:net')?.value ?? null,
        netRounds: [0,1,2].map(i => ev.results.find(r => r.key === `extreme:net${i}`)?.value ?? null),
      },
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
      `  youtube4k=${doc.youtube4k ? (doc.youtube4k.droppedFrames + '/' + doc.youtube4k.totalFrames + ' dropped @' + doc.youtube4k.height + 'p') : 'n/a'}` +
      `  stress=${doc.stress ? doc.stress.replace(/\s+/g, ' ') : 'n/a'}` +
      `  extreme[dom]=${doc.extreme.dom ?? 'n/a'}  extreme[js]=${doc.extreme.js ?? 'n/a'}` +
      `  extreme[webgl]=${doc.extreme.webgl ?? 'n/a'}  extreme[net]=${doc.extreme.net ?? 'n/a'}` +
      `  exit=${doc.exitCode}${doc.failure ? '  FAIL: ' + doc.failure : ''}`);
    console.log(`[bench]   -> ${file}`);
  }
  closeExtremeServer();
}

main().catch(e => { console.error('[bench] fatal:', e); closeExtremeServer(); process.exit(1); });
