R"LETHEJS(
(function () {
  'use strict';
  if (window.__letheMediaUpscaler) return;

  // 0 off, 1 linear, 2 FSR1 (EASU + moderate RCAS), 3 FSR1 + full RCAS.
  // hdr: 1 enables the SDR enhancer; alone it runs on the linear path.
  var hdr = __LETHE_INITIAL_HDR__ ? 1 : 0;
  var mode = (__LETHE_INITIAL_MODE__) || (hdr ? 1 : 0);
  var hdrVideo = new WeakMap();
  var entries = new WeakMap();
  var activeEntries = new Set();
  // A hostile or simply pathological page can contain thousands of visible
  // media nodes. Never let the enhancement layer turn that into thousands
  // of WebGL contexts/canvases and an unbounded GPU-resource commitment.
  // WebKit remains responsible for rendering all media outside this bounded
  // enhancement set, so this is a resource guard rather than a page limit.
  // Bound both the number of GPU contexts and the aggregate backing-store
  // size. A per-element cap alone still lets a hostile page reserve hundreds
  // of MiB by creating many 16MP overlays.
  var maxActiveEntries = 8;
  // Account for BOTH the decoded source texture and the output canvas. The
  // previous guard only charged the output canvas, so eight 8K sources could
  // still consume hundreds of MiB of GPU-visible texture storage while the
  // aggregate output budget appeared safe. Keep the whole enhancement layer
  // inside one explicit working-set budget.
  var maxTotalPixels = 67108864; // 64MP aggregate source + output working set
  var maxSourcePixels = 33554432; // 32MP / roughly 8K-class decoded input
  var activePixels = 0;
  var raf = 0;
  var geometryRaf = 0;
  var pendingMedia = new Set();
  var videoCallbacks = new WeakMap();

  var vs = '#version 300 es\n' +
    'in vec2 p; out vec2 uv; void main(){ uv=p*.5+.5; gl_Position=vec4(p,0.,1.); }';
  // Mode 1 samples with the GPU's bilinear filter. Modes 2/3 run AMD
  // FidelityFX Super Resolution 1.0 (MIT): EASU (edge-adaptive spatial
  // upsampling, 12 taps) into an output-sized texture, then RCAS (robust
  // contrast-adaptive sharpening) to the canvas. FSR 2+/4 are temporal and
  // need engine motion vectors a page cannot see, so FSR1 is the strongest
  // FSR a page-level pass can run. The HDR pass is an SDR enhancer (luma
  // S-curve + vibrance); decoded HDR (PQ/HLG) video is never routed here.
  // All decoded media remains page-local and WebGL still enforces CORS.
  var head = '#version 300 es\nprecision highp float;\nprecision highp int;\n' +
    'uniform sampler2D t; uniform vec4 uvRect; uniform vec4 destRect; uniform float hdr;\n' +
    'in vec2 uv; out vec4 o;\n' +
    'bool outside(){ return uv.x<destRect.x||uv.y<destRect.y||uv.x>destRect.x+destRect.z||uv.y>destRect.y+destRect.w; }\n' +
    'vec2 srcUV(){ return uvRect.xy+((uv-destRect.xy)/destRect.zw)*uvRect.zw; }\n' +
    'vec3 enh(vec3 c){ if(hdr<=0.) return c; float l=dot(c,vec3(.2126,.7152,.0722));\n' +
    ' float s=max(c.r,max(c.g,c.b))-min(c.r,min(c.g,c.b));\n' +
    ' c=mix(vec3(l),c,1.+hdr*.30*(1.-s));\n' +
    ' float nl=mix(l,l*l*(3.-2.*l),hdr*.35); c*=nl/max(l,1e-4); return clamp(c,0.,1.); }\n';
  var fsLinear = head +
    'void main(){ if(outside()) discard; vec4 c=texture(t,srcUV()); o=vec4(enh(c.rgb),c.a); }';
  var fsEasu = head +
    'vec3 F(ivec2 p){ return texelFetch(t,clamp(p,ivec2(0),textureSize(t,0)-1),0).rgb; }\n' +
    'float L(vec3 c){ return c.g+.5*(c.r+c.b); }\n' +
    'void st(inout vec2 dir,inout float len,float w,float lA,float lB,float lC,float lD,float lE){\n' +
    ' float lx=max(abs(lD-lC),abs(lC-lB)); lx=lx>0.?1./lx:0.; float dx=lD-lB; lx=clamp(abs(dx)*lx,0.,1.); lx*=lx;\n' +
    ' float ly=max(abs(lE-lC),abs(lC-lA)); ly=ly>0.?1./ly:0.; float dy=lE-lA; ly=clamp(abs(dy)*ly,0.,1.); ly*=ly;\n' +
    ' dir+=vec2(dx,dy)*w; len+=(lx+ly)*w; }\n' +
    'void tp(inout vec3 aC,inout float aW,vec2 off,vec2 dir,vec2 len,float lob,float clp,vec3 c){\n' +
    ' vec2 v=vec2(dot(off,dir),dot(off,vec2(-dir.y,dir.x)))*len; float d2=min(dot(v,v),clp);\n' +
    ' float wB=.4*d2-1.,wA=lob*d2-1.; wB*=wB; wA*=wA; wB=1.5625*wB-.5625; float w=wB*wA; aC+=c*w; aW+=w; }\n' +
    'void main(){ if(outside()) discard; vec2 su=srcUV();\n' +
    ' vec2 pp=su*vec2(textureSize(t,0))-.5; vec2 fp=floor(pp); pp-=fp; ivec2 i=ivec2(fp);\n' +
    ' vec3 b=F(i+ivec2(0,-1)),c=F(i+ivec2(1,-1)),e=F(i+ivec2(-1,0)),f=F(i),g=F(i+ivec2(1,0)),h=F(i+ivec2(2,0)),\n' +
    '  q=F(i+ivec2(-1,1)),j=F(i+ivec2(0,1)),k=F(i+ivec2(1,1)),l=F(i+ivec2(2,1)),n=F(i+ivec2(0,2)),r=F(i+ivec2(1,2));\n' +
    ' float bL=L(b),cL=L(c),eL=L(e),fL=L(f),gL=L(g),hL=L(h),iL=L(q),jL=L(j),kL=L(k),lL=L(l),nL=L(n),oL=L(r);\n' +
    ' vec2 dir=vec2(0); float len=0.;\n' +
    ' st(dir,len,(1.-pp.x)*(1.-pp.y),bL,eL,fL,gL,jL); st(dir,len,pp.x*(1.-pp.y),cL,fL,gL,hL,kL);\n' +
    ' st(dir,len,(1.-pp.x)*pp.y,fL,iL,jL,kL,nL); st(dir,len,pp.x*pp.y,gL,jL,kL,lL,oL);\n' +
    ' float dr=dot(dir,dir); dir=dr<1./32768.?vec2(1,0):dir*inversesqrt(dr);\n' +
    ' len*=.5; len*=len; float sk=dot(dir,dir)/max(abs(dir.x),abs(dir.y));\n' +
    ' vec2 l2=vec2(1.+(sk-1.)*len,1.-.5*len); float lob=.5+((.25-.04)-.5)*len; float clp=1./lob;\n' +
    ' vec3 mn=min(min(f,g),min(j,k)),mx=max(max(f,g),max(j,k)); vec3 aC=vec3(0); float aW=0.;\n' +
    ' tp(aC,aW,vec2(0,-1)-pp,dir,l2,lob,clp,b); tp(aC,aW,vec2(1,-1)-pp,dir,l2,lob,clp,c);\n' +
    ' tp(aC,aW,vec2(-1,1)-pp,dir,l2,lob,clp,q); tp(aC,aW,vec2(0,1)-pp,dir,l2,lob,clp,j);\n' +
    ' tp(aC,aW,-pp,dir,l2,lob,clp,f); tp(aC,aW,vec2(-1,0)-pp,dir,l2,lob,clp,e);\n' +
    ' tp(aC,aW,vec2(1,1)-pp,dir,l2,lob,clp,k); tp(aC,aW,vec2(2,1)-pp,dir,l2,lob,clp,l);\n' +
    ' tp(aC,aW,vec2(2,0)-pp,dir,l2,lob,clp,h); tp(aC,aW,vec2(1,0)-pp,dir,l2,lob,clp,g);\n' +
    ' tp(aC,aW,vec2(1,2)-pp,dir,l2,lob,clp,r); tp(aC,aW,vec2(0,2)-pp,dir,l2,lob,clp,n);\n' +
    ' o=vec4(min(mx,max(mn,aC/aW)),texture(t,su).a); }';
  // RCAS reads the EASU output 1:1 with texelFetch; `sharp` is FSR's
  // exp2(-stops) sharpness (1.0 = maximum).
  var fsRcas = head + 'uniform float sharp;\n' +
    'vec4 P(ivec2 p){ return texelFetch(t,clamp(p,ivec2(0),textureSize(t,0)-1),0); }\n' +
    'void main(){ if(outside()) discard; ivec2 p=ivec2(gl_FragCoord.xy);\n' +
    ' vec4 E=P(p); vec3 b=P(p+ivec2(0,-1)).rgb,d=P(p+ivec2(-1,0)).rgb,e=E.rgb,f=P(p+ivec2(1,0)).rgb,h=P(p+ivec2(0,1)).rgb;\n' +
    ' vec3 mn=min(min(b,d),min(f,h)),mx=max(max(b,d),max(f,h));\n' +
    ' vec3 hitMin=min(mn,e)/(4.*mx+1e-5); vec3 hitMax=(1.-max(mx,e))/(4.*min(mn,e)-4.-1e-5);\n' +
    ' vec3 lb=max(-hitMin,hitMax); float lobe=max(-.1875,min(max(lb.r,max(lb.g,lb.b)),0.))*sharp;\n' +
    ' vec3 c=(lobe*(b+d+f+h)+e)/(4.*lobe+1.); o=vec4(enh(clamp(c,0.,1.)),E.a); }';

  function compile(gl, src) {
    var pv=gl.createShader(gl.VERTEX_SHADER); gl.shaderSource(pv,vs); gl.compileShader(pv);
    var pf=gl.createShader(gl.FRAGMENT_SHADER); gl.shaderSource(pf,src); gl.compileShader(pf);
    if(!gl.getShaderParameter(pv,gl.COMPILE_STATUS)||!gl.getShaderParameter(pf,gl.COMPILE_STATUS)) return null;
    var pr=gl.createProgram(); gl.attachShader(pr,pv); gl.attachShader(pr,pf);
    gl.bindAttribLocation(pr,0,'p'); gl.linkProgram(pr);
    if(!gl.getProgramParameter(pr,gl.LINK_STATUS)) return null;
    var u=function(n){return gl.getUniformLocation(pr,n);};
    return {p:pr,uvRect:u('uvRect'),destRect:u('destRect'),hdr:u('hdr'),sharp:u('sharp'),t:u('t')};
  }
  function newTex(gl) {
    var tx=gl.createTexture(); gl.bindTexture(gl.TEXTURE_2D,tx);
    gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MIN_FILTER,gl.LINEAR); gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MAG_FILTER,gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_S,gl.CLAMP_TO_EDGE); gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_T,gl.CLAMP_TO_EDGE);
    return tx;
  }
  function makeGL(canvas) {
    var gl = canvas.getContext('webgl2', {alpha:true, premultipliedAlpha:false, antialias:false,
      powerPreference:'high-performance', desynchronized:true});
    if (!gl) return null;
    var lin=compile(gl,fsLinear), easu=compile(gl,fsEasu), rcas=compile(gl,fsRcas);
    if(!lin||!easu||!rcas) return null;
    var buf=gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER,buf);
    gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,1,1]),gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0); gl.vertexAttribPointer(0,2,gl.FLOAT,false,0,0);
    var mid=newTex(gl), fbo=gl.createFramebuffer();
    var tex=newTex(gl); gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL,true);
    return {gl:gl,tex:tex,lin:lin,easu:easu,rcas:rcas,mid:mid,fbo:fbo,midW:0,midH:0};
  }
  function uniforms(gl, pr, s) {
    gl.useProgram(pr.p); gl.uniform1i(pr.t,0);
    gl.uniform4f(pr.uvRect,s.ux,s.uy,s.uw,s.uh); gl.uniform4f(pr.destRect,s.dx,s.dy,s.dw,s.dh);
  }
  // Draws the already-uploaded source texture (unit 0) into the canvas.
  function drawFrame(e, s) {
    var g=e.gpu, gl=g.gl;
    gl.activeTexture(gl.TEXTURE0);
    gl.viewport(0,0,e.w,e.h);
    if(!s.fsr){
      uniforms(gl,g.lin,s); gl.uniform1f(g.lin.hdr,s.hdr);
      gl.bindTexture(gl.TEXTURE_2D,g.tex); gl.drawArrays(gl.TRIANGLE_STRIP,0,4); return;
    }
    if(g.midW!==e.w||g.midH!==e.h){
      gl.bindTexture(gl.TEXTURE_2D,g.mid);
      gl.texImage2D(gl.TEXTURE_2D,0,gl.RGBA8,e.w,e.h,0,gl.RGBA,gl.UNSIGNED_BYTE,null);
      gl.bindFramebuffer(gl.FRAMEBUFFER,g.fbo);
      gl.framebufferTexture2D(gl.FRAMEBUFFER,gl.COLOR_ATTACHMENT0,gl.TEXTURE_2D,g.mid,0);
      gl.clearColor(0,0,0,0); gl.clear(gl.COLOR_BUFFER_BIT);
      g.midW=e.w; g.midH=e.h;
    } else gl.bindFramebuffer(gl.FRAMEBUFFER,g.fbo);
    uniforms(gl,g.easu,s); gl.uniform1f(g.easu.hdr,0);
    gl.bindTexture(gl.TEXTURE_2D,g.tex); gl.drawArrays(gl.TRIANGLE_STRIP,0,4);
    gl.bindFramebuffer(gl.FRAMEBUFFER,null);
    uniforms(gl,g.rcas,s); gl.uniform1f(g.rcas.hdr,s.hdr); gl.uniform1f(g.rcas.sharp,s.sharp);
    gl.bindTexture(gl.TEXTURE_2D,g.mid); gl.drawArrays(gl.TRIANGLE_STRIP,0,4);
  }

  function eligible(el) {
    if (!(el instanceof HTMLImageElement || el instanceof HTMLVideoElement)) return false;
    if (!el.isConnected) return false;
    var w=el instanceof HTMLVideoElement ? el.videoWidth : el.naturalWidth;
    var h=el instanceof HTMLVideoElement ? el.videoHeight : el.naturalHeight;
    if (!w || !h) return false;
    var r=el.getBoundingClientRect();
    return r.width>=32 && r.height>=32 && r.right>0 && r.bottom>0 &&
      r.left<window.innerWidth && r.top<window.innerHeight;
  }

  function remove(e) {
    if(e.el) e.el.style.visibility='';
    if(e.el && e.el instanceof HTMLVideoElement && e.videoCallback != null && e.el.cancelVideoFrameCallback) {
      try { e.el.cancelVideoFrameCallback(e.videoCallback); } catch(_) {}
      videoCallbacks.delete(e.el);
    }
    // Explicitly release the page-local GPU context before detaching its
    // canvas. Waiting for WebKit's JavaScript GC to notice an unreachable
    // WebGL context can retain a large texture/context allocation for an
    // arbitrary interval, which is especially costly on media-heavy feeds.
    // Context loss is best-effort: the normal compositor remains responsible
    // for the source element and is never affected by this overlay cleanup.
    if(e.gpu && e.gpu.gl) {
      try {
        var lose=e.gpu.gl.getExtension('WEBGL_lose_context');
        if(lose) lose.loseContext();
      } catch(_) {}
    }
    if(e.canvas&&e.canvas.parentNode)e.canvas.parentNode.removeChild(e.canvas);
    if(e.el && visibilityObserver) visibilityObserver.unobserve(e.el);
    if(e.el && resizeObserver) resizeObserver.unobserve(e.el);
    entries.delete(e.el);
    activeEntries.delete(e);
    activePixels=Math.max(0,activePixels-(e.budgetPixels||0));
    e.budgetPixels=0;
  }

  function scheduleVideo(e) {
    if (!(e.el instanceof HTMLVideoElement) || mode===0) return;
    if (e.el.requestVideoFrameCallback) {
      if (e.videoCallback != null) return;
      var cb=function(){
        e.videoCallback=null;
        videoCallbacks.delete(e.el);
        if (!entries.has(e.el) || mode===0 || !e.el.isConnected) return;
        setup(e.el, true);
      };
      e.videoCallback=e.el.requestVideoFrameCallback(cb);
      videoCallbacks.set(e.el,e.videoCallback);
    }
  }

  function setup(el, videoFrame) {
    var e=entries.get(el);
    // requestVideoFrameCallback is already scoped to a live video element.
    // For an established entry, avoid another getBoundingClientRect() on
    // every decoded frame; the visibility/resize/scroll observers maintain
    // the cached geometry used by the fast path below.
    var fastCandidate = videoFrame && el instanceof HTMLVideoElement && e &&
      mode!==0 && e.mode===mode && e.frameState && e.canvas.style.display!=='none';
    if(!fastCandidate && (!eligible(el) || mode===0)) { if(e) remove(e); return; }
    if(!e){
      if(activeEntries.size>=maxActiveEntries) return;
      var c=document.createElement('canvas'); c.setAttribute('aria-hidden','true');
      c.style.cssText='position:fixed;z-index:2147483646;pointer-events:none;margin:0;padding:0;display:block;';
      c.addEventListener('webglcontextlost',function(ev){
        // A lost context must not leave the native media hidden behind a dead
        // overlay. Prevent the browser from attempting an unbounded recovery
        // cycle and tear the entry down instead.
        ev.preventDefault();
        var current=entries.get(el);
        if(current) remove(current);
      },{passive:false});
      document.documentElement.appendChild(c);
      e={el:el,canvas:c,gpu:makeGL(c),w:0,h:0}; entries.set(el,e); activeEntries.add(e);
    if(!e.gpu){ remove(e); return; }
    }

    // Decoded-video callbacks can arrive at display rate. Once geometry,
    // object-fit state, and the source texture allocation are stable, keep
    // this hot path entirely on the GPU: do not re-read layout, recompute
    // CSS transforms, or rebuild shader uniforms for every frame. Resize,
    // scroll, source changes, and mode changes fall through to the full path
    // below and refresh the cached state before the fast path is used again.
    var fastVideo = videoFrame && el instanceof HTMLVideoElement &&
      e.mode===mode && e.canvas.style.display!=='none' &&
      e.texW===el.videoWidth && e.texH===el.videoHeight && e.frameState;
    if(fastVideo){
      if(el.readyState < 2) { scheduleVideo(e); return; }
      try {
        var fastGl=e.gpu.gl;
        fastGl.activeTexture(fastGl.TEXTURE0);
        fastGl.bindTexture(fastGl.TEXTURE_2D,e.gpu.tex);
        fastGl.texSubImage2D(fastGl.TEXTURE_2D,0,0,0,fastGl.RGBA,fastGl.UNSIGNED_BYTE,el);
        drawFrame(e,e.frameState);
      } catch(_) { remove(e); return; }
      e.frames=(e.frames||0)+1;
      // Reuse the diagnostics object allocated by the full setup path.
      // requestVideoFrameCallback can run at 60/120 Hz; allocating a fresh
      // object for every decoded frame adds avoidable GC pressure to the
      // page's main JS world without changing the exposed diagnostics.
      var lf=e.lastFrame;
      if(lf){
        lf.sourceWidth=el.videoWidth; lf.sourceHeight=el.videoHeight;
        lf.outputWidth=e.w; lf.outputHeight=e.h;
        lf.scaleX=e.w/el.videoWidth; lf.scaleY=e.h/el.videoHeight;
        lf.time=el.currentTime;
      }
      scheduleVideo(e);
      return;
    }
    var r=el.getBoundingClientRect(), d=Math.min(window.devicePixelRatio||1,2);
    // A Retina 4K video would otherwise request an 8K backing canvas
    // (~132 MiB RGBA before GPU overhead). Keep the output at a bounded
    // working set while retaining the highest useful display resolution.
    var maxPixels=16777216, pixels=r.width*r.height*d*d;
    if(pixels>maxPixels) d*=Math.sqrt(maxPixels/pixels);
    var cw=Math.max(1,Math.round(r.width*d)), ch=Math.max(1,Math.round(r.height*d));
    var isVideo = el instanceof HTMLVideoElement;
    var sw=isVideo?el.videoWidth:el.naturalWidth, sh=isVideo?el.videoHeight:el.naturalHeight;
    // Do not copy pathological decoded surfaces into a WebGL texture. This
    // keeps the enhancement layer bounded even when a page supplies a very
    // large image/video frame; WebKit's normal compositor remains available.
    if(sw>8192 || sh>8192 || sw*sh>maxSourcePixels) { if(e) remove(e); return; }
    // CSS pixels are not the output resolution on Retina displays. Decide
    // whether scaling is useful from the actual canvas backing dimensions;
    // otherwise a 854x480 video rendered at 2x DPR would incorrectly look
    // like a 1:1 CSS-size video and never receive the upscaler.
    if (cw <= sw && ch <= sh && !hdr) {
      if (e) remove(e);
      return;
    }
    var oldBudget=e.budgetPixels||0;
    // Charge source + destination backing stores. This is deliberately a
    // conservative accounting model: driver-side allocations can exceed the
    // nominal RGBA dimensions, so staying below a hard pixel ceiling leaves
    // headroom for WebGL command/state overhead.
    var newBudget=cw*ch + sw*sh;
    if(activePixels-oldBudget+newBudget>maxTotalPixels){
      if(!oldBudget) return;
      remove(e);
      return;
    }
    if(oldBudget!==newBudget){ activePixels=activePixels-oldBudget+newBudget; e.budgetPixels=newBudget; }
    var geometryChanged=e.w!==cw||e.h!==ch||e.x!==r.left||e.y!==r.top;
    if(geometryChanged){e.canvas.width=cw; e.canvas.height=ch; e.canvas.style.left=r.left+'px'; e.canvas.style.top=r.top+'px'; e.canvas.style.width=r.width+'px'; e.canvas.style.height=r.height+'px'; e.w=cw; e.h=ch; e.x=r.left; e.y=r.top;}
    e.canvas.style.display=el.offsetWidth&&el.offsetHeight?'block':'none';
    var gl=e.gpu.gl; gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D,e.gpu.tex);
    var srcKey=isVideo ? (el.currentSrc||el.src||'') : (el.currentSrc||el.src||'');
    // Images only need a new upload when their source or display geometry
    // changes. Video frames, however, change while the element stays in the
    // same DOM node; upload and reconstruct only when WebKit reports a new
    // decoded frame, avoiding an unconditional 60 Hz readback/upload loop.
    if(isVideo && !videoFrame && !geometryChanged && e.srcKey===srcKey) {
      scheduleVideo(e);
      return;
    }
    if(!isVideo && !geometryChanged && e.srcKey===srcKey) return;
    if(isVideo && el.readyState < 2) return;
    // WebGL uploads tone-map HDR video to SDR. Leave PQ/HLG streams on the
    // native compositor so real HDR output survives; checked once per source.
    if(isVideo && window.VideoFrame){
      var hk=hdrVideo.get(el);
      if(!hk || hk.src!==srcKey){
        var tr='';
        try { var vf=new VideoFrame(el); tr=(vf.colorSpace&&vf.colorSpace.transfer)||''; vf.close(); } catch(_) {}
        hk={src:srcKey,hdr:tr==='pq'||tr==='hlg'}; hdrVideo.set(el,hk);
      }
      if(hk.hdr){ if(e) remove(e); return; }
    }
    try {
      // Keep the GPU allocation stable for video. texImage2D reallocates the
      // backing store on every decoded frame; texSubImage2D only uploads the
      // new pixels and is substantially cheaper on the WebKit GPU process.
      if (e.texW===sw && e.texH===sh) gl.texSubImage2D(gl.TEXTURE_2D,0,0,0,gl.RGBA,gl.UNSIGNED_BYTE,el);
      else { gl.texImage2D(gl.TEXTURE_2D,0,gl.RGBA,gl.RGBA,gl.UNSIGNED_BYTE,el); e.texW=sw; e.texH=sh; }
    } catch(_) { remove(e); return; }
    // Preserve the source element's object-fit behavior. Without this, a
    // CSS `object-fit: cover` video would be stretched rather than cropped.
    // The overlay remains the exact displayed rectangle while the shader
    // samples the corresponding sub-rectangle of the decoded frame.
    var cs=getComputedStyle(el), fit=cs.objectFit||'fill';
    var ux=0,uy=0,uw=1,uh=1, dx=0,dy=0,dw=1,dh=1, sar=sw/sh, dar=r.width/Math.max(r.height,1);
    var pos=(cs.objectPosition||'50% 50%').split(/\s+/), px=parseFloat(pos[0]), py=parseFloat(pos[1]);
    if(!isFinite(px)) px=50; if(!isFinite(py)) py=50;
    px=Math.max(0,Math.min(100,px))/100; py=Math.max(0,Math.min(100,py))/100;
    if(fit==='cover') {
      if(dar>sar) { uh=sar/dar; uy=(1-uh)*py; }
      else { uw=dar/sar; ux=(1-uw)*px; }
    } else if(fit==='contain') {
      if(dar>sar) { dw=sar/dar; dx=(1-dw)*px; }
      else { dh=dar/sar; dy=(1-dh)*py; }
    }
    // Linear mode deliberately takes the hardware-filtered fast path instead
    // of paying for the 16-tap reconstruction used by high-quality modes.
    var fsState={fsr:mode>=2,sharp:mode===3?1:0.7071,hdr:hdr,ux:ux,uy:uy,uw:uw,uh:uh,dx:dx,dy:dy,dw:dw,dh:dh};
    drawFrame(e,fsState);
    // Validate the first rendered frame before hiding WebKit's compositor
    // surface. A successful texImage2D call alone is not sufficient proof
    // that the media texture produced pixels on every WebKit configuration;
    // never leave the native video invisible behind an empty overlay.
    if(!e.validated){
      var probe=new Uint8Array(4);
      gl.readPixels(Math.floor(cw*.5),Math.floor(ch*.5),1,1,gl.RGBA,gl.UNSIGNED_BYTE,probe);
      if(probe[3]===0){ remove(e); return; }
      e.validated=true;
    }
    e.srcKey=srcKey;
    e.mode=mode;
    e.frameState=fsState;
    e.frames=(e.frames||0)+1;
    e.lastFrame={sourceWidth:sw,sourceHeight:sh,outputWidth:cw,outputHeight:ch,
      scaleX:cw/sw,scaleY:ch/sh,time:isVideo?el.currentTime:0};
    // Hide the source only after a successful draw; the overlay is
    // pointer-transparent so controls remain on the original element.
    el.style.visibility='hidden';
    scheduleVideo(e);
  }

  // Scrolling changes the overlay's viewport coordinates but does not change
  // the decoded frame. Keep this path geometry-only: the old implementation
  // rescanned every <img>/<video> and re-ran eligibility checks on every
  // scroll event, which is disproportionately expensive on media-heavy
  // pages. Frame uploads remain exclusively on decoded-frame callbacks.
  function syncGeometry(){
    geometryRaf=0;
    activeEntries.forEach(function(e){
      if(!e.el.isConnected){ remove(e); return; }
      var r=e.el.getBoundingClientRect();
      if(r.width<1 || r.height<1){ e.canvas.style.display='none'; return; }
      var x=r.left, y=r.top;
      if(e.x!==x || e.y!==y || e.canvas.style.width!==r.width+'px' || e.canvas.style.height!==r.height+'px'){
        e.canvas.style.left=x+'px'; e.canvas.style.top=y+'px';
        e.canvas.style.width=r.width+'px'; e.canvas.style.height=r.height+'px';
        e.x=x; e.y=y;
      }
      e.canvas.style.display='block';
    });
  }

  function scheduleGeometry(){
    if(mode!==0 && !geometryRaf) geometryRaf=requestAnimationFrame(syncGeometry);
  }

  function scan(){ raf=0; if(mode===0)return;
    // Drop detached media and their overlay canvases. This also prevents a
    // navigation-heavy page from accumulating stale GPU contexts.
    activeEntries.forEach(function(e){ if(!e.el.isConnected) remove(e); });
    document.querySelectorAll('img,video').forEach(function(el){
    // Native video controls are part of the video compositor surface. Do not
    // cover them with our canvas; controlled video stays untouched rather
    // than losing playback/fullscreen/quality controls.
    if(el instanceof HTMLVideoElement && el.controls) return;
    if(visibilityObserver) visibilityObserver.observe(el);
    if(resizeObserver) resizeObserver.observe(el);
    setup(el);
  }); }
  // Coalesce DOM/resize/load churn into one scan per animation frame.
  // Video frames already have their own decoded-frame callback, so an idle
  // page no longer pays for a periodic full-media scan every 50 ms.
  function start(){ if(!raf) raf=requestAnimationFrame(scan); }

  window.__letheMediaUpscalerSetMode=function(m,h){
    if(h!==undefined) hdr=h?1:0;
    mode=(m|0)||(hdr?1:0);
    // Force the next pass through the full path so cached frame state
    // (sharpness, HDR) is rebuilt for every live overlay.
    activeEntries.forEach(function(e){ e.srcKey=null; e.mode=-1; });
    if(mode===0){
      activeEntries.forEach(function(e){remove(e);});
      activeEntries.clear();
      entries=new WeakMap();
      return;
    }
    start();
  };
  window.__letheMediaUpscaler={
    setMode:window.__letheMediaUpscalerSetMode,
    state:function(){
      var active=[];
      activeEntries.forEach(function(e){
        if(e.lastFrame) active.push({frames:e.frames||0,lastFrame:e.lastFrame,
          canvasWidth:e.canvas.width,canvasHeight:e.canvas.height});
      });
      return {mode:mode,hdr:hdr,active:active.length,entries:active};
    }
  };
  var visibilityObserver = 'IntersectionObserver' in window ? new IntersectionObserver(function(list){
    list.forEach(function(item){
      if(item.isIntersecting) setup(item.target);
      else { var e=entries.get(item.target); if(e) { e.canvas.style.display='none'; } }
    });
  }, {root:null,rootMargin:'256px',threshold:0}) : null;
  var resizeObserver = 'ResizeObserver' in window ? new ResizeObserver(function(list){
    list.forEach(function(item){ if(entries.has(item.target)) setup(item.target); });
  }) : null;
  new MutationObserver(function(list){
    // Avoid rescanning the entire document for every framework mutation.
    // Collect only newly-added media and let one animation-frame pass process
    // the batch. This matters on feeds that continuously append thumbnails.
    list.forEach(function(m){
      m.addedNodes.forEach(function(n){
        if(n.nodeType!==1) return;
        if(n.matches && n.matches('img,video')) pendingMedia.add(n);
        if(n.querySelectorAll) n.querySelectorAll('img,video').forEach(function(el){pendingMedia.add(el);});
      });
    });
    if(pendingMedia.size){
      if(!raf) raf=requestAnimationFrame(function(){
        raf=0;
        if(mode===0){pendingMedia.clear();return;}
        pendingMedia.forEach(function(el){
          if(el.isConnected) setup(el);
          if(visibilityObserver) visibilityObserver.observe(el);
          if(resizeObserver) resizeObserver.observe(el);
        });
        pendingMedia.clear();
      });
    }
  }).observe(document.documentElement,{subtree:true,childList:true});
  window.addEventListener('resize',start,{passive:true});
  window.addEventListener('scroll',scheduleGeometry,{passive:true});
  document.addEventListener('load',start,true);
  document.addEventListener('loadeddata',start,true);
  start();
})();
)LETHEJS"
