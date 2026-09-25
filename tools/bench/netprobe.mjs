// netprobe.mjs <label> <browser-binary> [args...] - 300 concurrent 1 KB
// fetches, 5 self-reloading rounds, median of rounds 2-5. Works with any
// binary (%P = temp profile dir, %U = page URL). Used to compare stock
// cefclient, Lethe CEF and Chrome without per-browser automation.
// Same 300-fetch page, but the page reports to /report and reloads itself
// 5 times, so any browser binary can be measured without its automation.
import http from 'node:http'; import { spawn } from 'node:child_process'; import { mkdtempSync } from 'node:fs'; import { tmpdir } from 'node:os';
const [,, label, bin, ...extra] = process.argv; const N = 300, ROUNDS = 5, results = [];
const page = `<!doctype html><script>
var N=${N},t0=performance.now(),ps=[];for(var i=0;i<N;i++)ps.push(fetch('/f'+i+'.bin?'+Math.random(),{cache:'no-store'}).then(r=>r.arrayBuffer()));
Promise.all(ps).then(function(){var rps=N*1000/(performance.now()-t0);
fetch('/report?rps='+rps.toFixed(0)).then(function(){var r=+(location.hash.slice(1)||0)+1;if(r<${ROUNDS}){location.hash=r;location.reload();}});});</script>`;
const payload = Buffer.alloc(1024, 7);
let child, done;
const srv = http.createServer((q, s) => {
  if (q.url.startsWith('/report')) { results.push(+new URL(q.url, 'http://x').searchParams.get('rps')); s.end('ok');
    if (results.length === ROUNDS) done(); return; }
  if (q.url.startsWith('/f')) { s.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' }); s.end(payload); return; }
  s.writeHead(200, { 'Content-Type': 'text/html' }); s.end(page);
}).listen(0, '127.0.0.1', () => {
  const url = `http://127.0.0.1:${srv.address().port}/`;
  const prof = mkdtempSync(tmpdir() + '/np-');
  child = spawn(bin, [...extra.map(a => a.replace('%P', prof).replace('%U', url)), ...(extra.some(a => a.includes('%U')) ? [] : [url])], { stdio: 'ignore', env: { ...process.env, LETHE_CEF_USER_DATA_DIR: prof, LETHE_KEEP_FRONT: '1' } });
});
await new Promise(r => { done = r; setTimeout(r, 90000); });
child.kill('SIGTERM'); srv.close();
const warm = results.slice(1).sort((a, b) => a - b);
console.log(label.padEnd(24), 'rounds', results.join(','), ' median(warm)', warm[warm.length >> 1]);
process.exit(0);
