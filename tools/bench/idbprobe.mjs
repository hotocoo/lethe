import http from 'node:http'; import { spawn } from 'node:child_process'; import { mkdtempSync } from 'node:fs'; import { tmpdir } from 'node:os';
const [,, label, bin, ...extra] = process.argv;
const page = `<!doctype html><script>
var q=indexedDB.open('p'+Date.now(),1);q.onupgradeneeded=function(){q.result.createObjectStore('s',{keyPath:'id'});};
q.onsuccess=function(){var db=q.result,tx=db.transaction('s','readwrite'),st=tx.objectStore('s');
for(var i=0;i<20000;i++)st.put({id:i,name:'r'+i,v:i*3,tags:['a','b']});
tx.oncomplete=function(){var t=performance.now(),n=0;
 db.transaction('s').objectStore('s').openCursor().onsuccess=function(e){var c=e.target.result;if(c){n++;c.continue();return;}
  var cur=performance.now()-t;t=performance.now();
  db.transaction('s').objectStore('s').getAll().onsuccess=function(e2){var ga=performance.now()-t;
   var t3=performance.now(),k=0;var ch=function(){var tr=db.transaction('s').objectStore('s');var j=0;(function g(){tr.get(k++).onsuccess=function(){if(++j<2000)g();else fin();};})();};
   var fin=function(){fetch('/r?c='+cur.toFixed(0)+'&ga='+ga.toFixed(0)+'&get2k='+(performance.now()-t3).toFixed(0));};ch();};};};};</script>`;
let child; const srv = http.createServer((q, s) => { if (q.url.startsWith('/r')) { console.log(label.padEnd(14), q.url.slice(3)); s.end(); child.kill(); srv.close(); process.exit(0); } s.writeHead(200,{'Content-Type':'text/html'}); s.end(page); })
.listen(0, '127.0.0.1', () => { const prof = mkdtempSync(tmpdir()+'/ip-'); child = spawn(bin, [...extra, `http://127.0.0.1:${srv.address().port}/`], { stdio:'ignore', env:{...process.env, LETHE_CEF_USER_DATA_DIR:prof, LETHE_KEEP_FRONT:'1'} }); });
setTimeout(()=>{console.log(label,'timeout');child.kill();process.exit(1)},60000);
