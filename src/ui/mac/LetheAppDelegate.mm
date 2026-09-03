// LetheAppDelegate.mm - application lifecycle, menu bar, tab/window factory

#import "ui/mac/LetheShell.h"
#import "ui/mac/LetheBookmarks.h"
#import "ui/mac/LetheHistory.h"
#import "ui/mac/LethePreferences.h"
#import "ui/mac/LethePluginLoader.h"
#import "ui/mac/LetheSession.h"
#import "ui/mac/LethePermissions.h"
#import "ui/mac/LetheTabSearch.h"
#import "ui/mac/LetheSettings.h"
#import <Network/Network.h>
#import <objc/runtime.h>

#include <iostream>

#include "browser/url_input.h"
#include "plugins/plugin_registry.h"
#include "security/tracker_blocklist.h"

// WebKit does not expose its private media compositor surfaces to an
// embedder.  Install a page-local GPU scaler instead: it handles the media
// elements we can legally sample (same-origin/CORS-clean images and video),
// while the renderer's MetalFX path remains available for native RGBA frames.
NSString* LetheMediaUpscalerScript(void) {
    NSInteger initialMode = 0;
    const char* envUpscaler = getenv("LETHE_UPSCALER");
    if (envUpscaler && *envUpscaler) {
        std::string v = envUpscaler;
        for (char& ch : v) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        if (v == "linear") initialMode = 1;
        else if (v == "metalfx-sharp") initialMode = 3;
        else if (v == "metalfx" || v == "metalfx-spatial" || v == "fsr") initialMode = 2;
    } else {
        LethePreferences* p = [LethePreferences shared];
        if (p.upscaler == LetheUpscalerLinear) initialMode = 1;
        else if (p.upscaler == LetheUpscalerFSR1) initialMode = 2;
        else if (p.upscaler == LetheUpscalerDLSSLike) initialMode = 3;
    }
    return [(@R"JS(
(function () {
  'use strict';
  if (window.__letheMediaUpscaler) return;

  var mode = __LETHE_INITIAL_MODE__; // 0 off, 1 linear, 2 high quality, 3 high quality + sharp
  var entries = new WeakMap();
  var activeEntries = new Set();
  var raf = 0;
  var videoCallbacks = new WeakMap();

  var vs = '#version 300 es\n' +
    'in vec2 p; out vec2 uv; void main(){ uv=p*.5+.5; gl_Position=vec4(p,0.,1.); }';
  // 16-tap bicubic reconstruction plus a restrained edge-adaptive RCAS-like
  // sharpen.  This is deliberately page-local: no decoded media bytes leave
  // the renderer process and CORS rules are still enforced by WebGL.
  var fs = '#version 300 es\nprecision highp float;\n' +
    'uniform sampler2D t; uniform vec2 texel; uniform float sharp; uniform vec4 uvRect; uniform vec4 destRect;\n' +
    'in vec2 uv; out vec4 o;\n' +
    'float w(float x){x=abs(x); if(x<1.0)return 1.0-2.5*x*x+1.5*x*x*x; if(x<2.0)return 2.0-4.0*x+2.5*x*x-.5*x*x*x; return 0.0;}\n' +
    'void main(){ if(uv.x<destRect.x||uv.y<destRect.y||uv.x>destRect.x+destRect.z||uv.y>destRect.y+destRect.w) discard; vec2 luv=(uv-destRect.xy)/destRect.zw; vec2 suv=uvRect.xy+luv*uvRect.zw; vec2 q=suv/texel; vec2 b=floor(q-.5); vec2 f=q-.5-b; vec4 s=vec4(0); float ws=0.;\n' +
    'for(int j=-1;j<=2;j++) for(int i=-1;i<=2;i++){float ww=w(float(i)-f.x)*w(float(j)-f.y); s+=texture(t,(b+vec2(i,j)+.5)*texel)*ww; ws+=ww;}\n' +
    'vec4 c=s/max(ws,.0001); vec3 n=texture(t,suv+vec2(0,-texel.y)).rgb, e=texture(t,suv+vec2(texel.x,0)).rgb, ss=texture(t,suv+vec2(0,texel.y)).rgb, ww=texture(t,suv+vec2(-texel.x,0)).rgb;\n' +
    'vec3 avg=(n+e+ss+ww)*.25; vec3 detail=c.rgb-avg; float edge=clamp(length(detail)*4.0,0.,1.); c.rgb=clamp(c.rgb+detail*sharp*(1.-edge*.65),0.,1.); o=c; }';

  function makeGL(canvas) {
    var gl = canvas.getContext('webgl2', {alpha:true, premultipliedAlpha:false, antialias:false});
    if (!gl) return null;
    var pv=gl.createShader(gl.VERTEX_SHADER); gl.shaderSource(pv,vs); gl.compileShader(pv);
    var pf=gl.createShader(gl.FRAGMENT_SHADER); gl.shaderSource(pf,fs); gl.compileShader(pf);
    if(!gl.getShaderParameter(pv,gl.COMPILE_STATUS)||!gl.getShaderParameter(pf,gl.COMPILE_STATUS)) return null;
    var pr=gl.createProgram(); gl.attachShader(pr,pv); gl.attachShader(pr,pf); gl.linkProgram(pr);
    if(!gl.getProgramParameter(pr,gl.LINK_STATUS)) return null;
    var buf=gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER,buf);
    gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,1,1]),gl.STATIC_DRAW);
    var a=gl.getAttribLocation(pr,'p'); gl.enableVertexAttribArray(a); gl.vertexAttribPointer(a,2,gl.FLOAT,false,0,0);
    var tex=gl.createTexture(); gl.bindTexture(gl.TEXTURE_2D,tex); gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MIN_FILTER,gl.LINEAR); gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MAG_FILTER,gl.LINEAR); gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_S,gl.CLAMP_TO_EDGE); gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_T,gl.CLAMP_TO_EDGE);
    return {gl:gl,program:pr,tex:tex,texel:gl.getUniformLocation(pr,'texel'),sharp:gl.getUniformLocation(pr,'sharp'),uvRect:gl.getUniformLocation(pr,'uvRect'),destRect:gl.getUniformLocation(pr,'destRect')};
  }

  function eligible(el) {
    if (!(el instanceof HTMLImageElement || el instanceof HTMLVideoElement)) return false;
    if (!el.isConnected) return false;
    var w=el instanceof HTMLVideoElement ? el.videoWidth : el.naturalWidth;
    var h=el instanceof HTMLVideoElement ? el.videoHeight : el.naturalHeight;
    if (!w || !h) return false;
    var r=el.getBoundingClientRect();
    return r.width>=32 && r.height>=32;
  }

  function remove(e) {
    if(e.el) e.el.style.visibility='';
    if(e.el && e.el instanceof HTMLVideoElement && e.videoCallback != null && e.el.cancelVideoFrameCallback) {
      try { e.el.cancelVideoFrameCallback(e.videoCallback); } catch(_) {}
      videoCallbacks.delete(e.el);
    }
    if(e.canvas&&e.canvas.parentNode)e.canvas.parentNode.removeChild(e.canvas);
    entries.delete(e.el);
    activeEntries.delete(e);
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
    if(!eligible(el) || mode===0) { if(entries.has(el)) remove(entries.get(el)); return; }
    var e=entries.get(el);
    if(!e){
      var c=document.createElement('canvas'); c.setAttribute('aria-hidden','true');
      c.style.cssText='position:fixed;z-index:2147483646;pointer-events:none;margin:0;padding:0;display:block;';
      document.documentElement.appendChild(c);
      e={el:el,canvas:c,gpu:makeGL(c),w:0,h:0}; entries.set(el,e); activeEntries.add(e);
    if(!e.gpu){ remove(e); return; }
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
    // CSS pixels are not the output resolution on Retina displays. Decide
    // whether scaling is useful from the actual canvas backing dimensions;
    // otherwise a 854x480 video rendered at 2x DPR would incorrectly look
    // like a 1:1 CSS-size video and never receive the upscaler.
    if (cw <= sw && ch <= sh) {
      if (e) remove(e);
      return;
    }
    var geometryChanged=e.w!==cw||e.h!==ch||e.x!==r.left||e.y!==r.top;
    if(geometryChanged){e.canvas.width=cw; e.canvas.height=ch; e.canvas.style.left=r.left+'px'; e.canvas.style.top=r.top+'px'; e.canvas.style.width=r.width+'px'; e.canvas.style.height=r.height+'px'; e.w=cw; e.h=ch; e.x=r.left; e.y=r.top;}
    e.canvas.style.display=el.offsetWidth&&el.offsetHeight?'block':'none';
    var gl=e.gpu.gl; gl.viewport(0,0,cw,ch); gl.useProgram(e.gpu.program); gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D,e.gpu.tex);
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
    try { gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true); gl.texImage2D(gl.TEXTURE_2D,0,gl.RGBA,gl.RGBA,gl.UNSIGNED_BYTE,el); } catch(_) { remove(e); return; }
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
    gl.uniform2f(e.gpu.texel,1/sw,1/sh); gl.uniform1f(e.gpu.sharp,mode===3?.62:mode===2?.42:0.);
    gl.uniform4f(e.gpu.uvRect,ux,uy,uw,uh); gl.uniform4f(e.gpu.destRect,dx,dy,dw,dh); gl.drawArrays(gl.TRIANGLE_STRIP,0,4);
    if(gl.getError()!==gl.NO_ERROR) { remove(e); return; }
    // Validate the first rendered frame before hiding WebKit's compositor
    // surface. A successful texImage2D call alone is not sufficient proof
    // that the media texture produced pixels on every WebKit configuration;
    // never leave the native video invisible behind an empty overlay.
    if(!e.validated){
      var probe=new Uint8Array(4);
      gl.readPixels(Math.floor(cw*.5),Math.floor(ch*.5),1,1,gl.RGBA,gl.UNSIGNED_BYTE,probe);
      if(gl.getError()!==gl.NO_ERROR || probe[3]===0){ remove(e); return; }
      e.validated=true;
    }
    e.srcKey=srcKey;
    e.frames=(e.frames||0)+1;
    e.lastFrame={sourceWidth:sw,sourceHeight:sh,outputWidth:cw,outputHeight:ch,
      scaleX:cw/sw,scaleY:ch/sh,time:isVideo?el.currentTime:0};
    // Hide the source only after a successful draw; the overlay is
    // pointer-transparent so controls remain on the original element.
    el.style.visibility='hidden';
    scheduleVideo(e);
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
    setup(el);
  }); }
  // Coalesce DOM/scroll/resize/load churn into one scan per animation frame.
  // Video frames already have their own decoded-frame callback, so an idle
  // page no longer pays for a periodic full-media scan every 50 ms.
  function start(){ if(!raf) raf=requestAnimationFrame(scan); }

  window.__letheMediaUpscalerSetMode=function(m){
    mode=m|0;
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
      return {mode:mode,active:active.length,entries:active};
    }
  };
  new MutationObserver(function(){start();}).observe(document.documentElement,{subtree:true,childList:true});
  window.addEventListener('resize',start,{passive:true}); window.addEventListener('scroll',start,{passive:true});
  document.addEventListener('load',start,true);
  document.addEventListener('loadeddata',start,true);
  start();
})();
)JS") stringByReplacingOccurrencesOfString:@"__LETHE_INITIAL_MODE__"
                    withString:[NSString stringWithFormat:@"%ld", (long)initialMode]];
}

@interface LetheAppDelegate () {
    lethe::ShellContext* ctx_;
    LethePolicyGate* gate_;
    NSMutableArray<BrowserWindowController*>* controllers_;
    WKWebsiteDataStore* dataStore_;
    NSMutableSet<NSString*>* httpAllowedHosts_;
    WKUserContentController* userContent_;   // shared: one rule list, every tab
    NSUInteger trackerRuleCount_;
    WKContentRuleList* trackerRuleList_;
    BOOL proxyApplied_;
    LetheAutomation* automation_;
}
@end

@implementation LetheAppDelegate

@synthesize gate = gate_;

- (instancetype)initWithContext:(lethe::ShellContext*)ctx {
    if ((self = [super init])) {
        ctx_ = ctx;
        gate_ = [[LethePolicyGate alloc] initWithContext:*ctx];
        controllers_ = [NSMutableArray array];
        proxyApplied_ = NO;
        // Whenever the unified Settings window saves (Cmd+Enter or Save
        // button), [LethePreferences save] posts this. We need to repush
        // the runtime knobs to the live engine; that's exactly what
        // applyPreferences does for tracker rules, UA and https-first.
        // The persistent-cookies case additionally fires its own alert.
        [[NSNotificationCenter defaultCenter] addObserver:self
            selector:@selector(preferencesChanged:)
            name:LethePreferencesDidChangeNotification object:nil];
    }
    return self;
}

- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }

- (void)preferencesChanged:(NSNotification*)note {
    (void)note;
    [self applyPreferences];
    // Persistent cookies is a per-process choice: the WKWebsiteDataStore
    // is fixed at webView creation time. Tell the user it needs a relaunch.
    static BOOL lastPersistent = NO;
    LethePreferences* p = [LethePreferences shared];
    if (p.persistentCookies != lastPersistent) {
        lastPersistent = p.persistentCookies;
        NSAlert* a = [[NSAlert alloc] init];
        a.messageText = @"Restart Lethe to apply";
        a.informativeText = @"Persistent cookies are decided when a window opens. New windows will use this setting immediately; close existing windows or relaunch for them to pick it up too.";
        [a runModal];
    }
}

- (lethe::ShellContext*)context { return ctx_; }

#pragma mark - Lifecycle

- (NSUInteger)trackerRuleCount { return trackerRuleCount_; }

- (WKUserContentController*)userContentController {
    if (!userContent_) {
        userContent_ = [[WKUserContentController alloc] init];
        // The script is installed once, before any page document exists.
        // It only activates when the persisted Settings mode is non-zero.
        WKUserScript* media = [[WKUserScript alloc]
            initWithSource:LetheMediaUpscalerScript()
              injectionTime:WKUserScriptInjectionTimeAtDocumentStart
           forMainFrameOnly:YES];
        [userContent_ addUserScript:media];
    }
    return userContent_;
}

// Compile (or fetch from WebKit's on-disk store) the built-in tracker rules
// and attach them to the shared user-content controller BEFORE the first
// web view exists, so even the very first navigation is protected. The
// store is keyed by a hash of the list: editing trackers.txt recompiles.
- (void)prepareTrackerProtection:(void (^)(void))done {
    if (!ctx_->trackerBlocking) {
        std::cout << "[lethe] tracker protection: OFF (--no-tracker-block)" << std::endl;
        done();
        return;
    }
    const lethe::TrackerBlocklist& list = lethe::builtinTrackerBlocklist();
    const NSUInteger count = list.domains.size() + list.pathPatterns.size();
    NSString* ident = @(lethe::trackerRulesIdentifier(list).c_str());
    WKContentRuleListStore* store = [WKContentRuleListStore defaultStore];
    __weak LetheAppDelegate* weakSelf = self;
    void (^install)(WKContentRuleList*, NSString*) = ^(WKContentRuleList* rules, NSString* how) {
        LetheAppDelegate* self = weakSelf;
        if (!self) return;
        [[self userContentController] addContentRuleList:rules];
        self->trackerRuleList_ = rules;
        self->trackerRuleCount_ = count;
        std::cout << "[lethe] tracker protection: " << count << " third-party rules ("
                  << how.UTF8String << ")" << std::endl;
    };
    [store lookUpContentRuleListForIdentifier:ident
                            completionHandler:^(WKContentRuleList* found, NSError* lookupErr) {
        (void)lookupErr;
        if (found) { install(found, @"cached"); done(); return; }
        NSString* json = @(lethe::trackerContentRulesJson(list).c_str());
        const NSTimeInterval t0 = [NSDate timeIntervalSinceReferenceDate];
        [store compileContentRuleListForIdentifier:ident
                            encodedContentRuleList:json
                                 completionHandler:^(WKContentRuleList* compiled, NSError* err) {
            if (compiled) {
                install(compiled, [NSString stringWithFormat:@"compiled in %.0f ms",
                                   ([NSDate timeIntervalSinceReferenceDate] - t0) * 1000.0]);
            } else {
                std::cerr << "[lethe] tracker protection: rule compile failed: "
                          << (err.localizedDescription.UTF8String ?: "unknown") << std::endl;
            }
            done();
        }];
    }];
}

- (void)applicationDidFinishLaunching:(NSNotification*)note {
    (void)note;
    // A binary launched from the command line (benchmarks, e2e) can start
    // without a regular activation policy; force it so the window can win
    // focus and WebKit keeps requestAnimationFrame running.
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [self buildMenuBar];
    [self prepareTrackerProtection:^{ [self openInitialWindow]; }];
}

- (void)openInitialWindow {
    NSArray<NSDictionary*>* saved = @[];
    if (ctx_->cfg.initialUrl.empty() && ctx_->e2eScript.empty()) saved = [[LetheSession shared] load];
    NSString* initial = saved.count ? saved.firstObject[@"url"]
        : (ctx_->cfg.initialUrl.empty() ? nil : @(ctx_->cfg.initialUrl.c_str()));
    BrowserWindowController* c = [self openWindowWithURL:initial];
    // Chrome-style: the tab strip is always there, even with one tab.
    if (c.window.tabGroup && !c.window.tabGroup.tabBarVisible) {
        [c.window toggleTabBar:nil];
    }
    [NSApp activateIgnoringOtherApps:YES];
    if (!ctx_->e2eScript.empty()) {
        LetheAutomation* auto_ = [[LetheAutomation alloc]
            initWithDelegate:self scriptPath:@(ctx_->e2eScript.c_str())];
        automation_ = auto_;
        [auto_ start];
    }
    // Apply saved preferences to the just-opened window (UA, etc.).
    [self applyPreferences];
}

- (NSArray<BrowserWindowController*>*)controllers { return [controllers_ copy]; }

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app {
    (void)app;
    return NO;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication*)app hasVisibleWindows:(BOOL)visible {
    (void)app;
    if (!visible) [self openWindowWithURL:nil];
    return YES;
}

- (void)application:(NSApplication*)app openURLs:(NSArray<NSURL*>*)urls {
    (void)app;
    for (NSURL* u in urls) {
        NSWindow* key = [NSApp keyWindow];
        [self openTabWithURL:u.absoluteString fromWindow:key webView:nil];
    }
}

- (void)applicationWillTerminate:(NSNotification*)note {
    (void)note;
    NSMutableArray<NSDictionary*>* snap = [NSMutableArray array];
    for (BrowserWindowController* c in [controllers_ copy]) {
        NSString* url = c.webView.URL.absoluteString;
        if (url.length && [url hasPrefix:@"http"]) [snap addObject:@{@"url":url, @"title":c.webView.title ?: url}];
        [c.window close];
    }
    [[LetheSession shared] saveWindows:snap];
    // The heavy shutdown (stopping the policy proxy + joining its workers,
    // tearing down the engine) can block for a while if live tunnels are
    // open. Run it off the main thread so the app always quits promptly
    // instead of hanging until force-quit. It is best-effort: if the process
    // exits first, the OS reclaims the resources.
    if (ctx_->onTerminate) {
        auto hook = std::move(ctx_->onTerminate);
        ctx_->onTerminate = nullptr;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            hook();
        });
    }
}

#pragma mark - WebKit configuration

- (WKWebsiteDataStore*)dataStore {
    // Persistent cookies now live in preferences (CLI flag still wins at
    // launch; runtime toggles take effect for new webViews).
    BOOL wantPersistent = [[LethePreferences shared] persistentCookies] || ctx_->persistent;
    if (!dataStore_) {
        dataStore_ = wantPersistent
            ? [WKWebsiteDataStore defaultDataStore]
            : [WKWebsiteDataStore nonPersistentDataStore];
        std::cout << "[lethe] site data store: "
                  << (wantPersistent ? "persistent" : "ephemeral (incognito)")
                  << std::endl;
    }
    if (!proxyApplied_ && ctx_->proxyPort > 0) {
        proxyApplied_ = YES;
        if ([self bindStoreToProxy:dataStore_]) {
            std::cout << "[lethe] WebKit traffic routed through policy proxy "
                         "127.0.0.1:" << ctx_->proxyPort << " (subresource enforcement on)"
                      << std::endl;
        } else {
            std::cout << "[lethe] macOS < 14: no per-datastore proxy API; "
                         "navigation gate only" << std::endl;
        }
    }
    return dataStore_;
}

- (BOOL)bindStoreToProxy:(WKWebsiteDataStore*)store {
    if (ctx_->proxyPort <= 0) return NO;
    if (@available(macOS 14.0, *)) {
        const std::string port = std::to_string(ctx_->proxyPort);
        nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", port.c_str());
        nw_proxy_config_t pc = nw_proxy_config_create_http_connect(ep, nil);
        if (!ctx_->proxyAuthToken.empty()) {
            // The proxy refuses (407) anything without this per-launch
            // secret, so other local processes cannot ride Lethe's
            // policy identity or VPN tunnel.
            nw_proxy_config_set_username_and_password(
                pc, "lethe", ctx_->proxyAuthToken.c_str());
        }
        store.proxyConfigurations = @[pc];
        return YES;
    }
    return NO;
}

- (WKWebsiteDataStore*)makeOblivionStore {
    WKWebsiteDataStore* store = [WKWebsiteDataStore nonPersistentDataStore];
    [self bindStoreToProxy:store];
    return store;
}

- (WKWebViewConfiguration*)webViewConfiguration {
    return [self webViewConfigurationWithStore:nil];
}

- (WKWebViewConfiguration*)webViewConfigurationWithStore:(WKWebsiteDataStore*)store {
    WKWebViewConfiguration* c = [[WKWebViewConfiguration alloc] init];
    c.websiteDataStore = store ?: [self dataStore];
    c.userContentController = [self userContentController];
    c.defaultWebpagePreferences.allowsContentJavaScript = YES;
    // Popup blocking like Chrome: window.open needs a user gesture.
    c.preferences.javaScriptCanOpenWindowsAutomatically = NO;
    c.preferences.fraudulentWebsiteWarningEnabled = YES;
#if DEBUG
    // Keep Web Inspector available for developer builds only. Shipping
    // builds must not expose developer tooling to arbitrary page content.
    [c.preferences setValue:@YES forKey:@"developerExtrasEnabled"];
#endif
    if (@available(macOS 12.3, *)) {
        c.preferences.elementFullscreenEnabled = YES;
    }
    return c;
}

#pragma mark - Windows and tabs

- (BrowserWindowController*)makeController:(WKWebView*)existing {
    return [self makeController:existing store:nil oblivion:NO];
}

- (BrowserWindowController*)makeController:(WKWebView*)existing
                                      store:(WKWebsiteDataStore*)store
                                   oblivion:(BOOL)oblivion {
    BrowserWindowController* c =
        [[BrowserWindowController alloc] initWithContext:ctx_ gate:gate_ webView:existing
                                               dataStore:store oblivion:oblivion];
    [controllers_ addObject:c];
    return c;
}

- (BrowserWindowController*)openWindowWithURL:(NSString*)url {
    BrowserWindowController* c = [self makeController:nil];
    // Keep the new window standalone even when the system prefers tabs.
    c.window.tabbingMode = NSWindowTabbingModeDisallowed;
    [c showWindow:nil];
    [c.window makeKeyAndOrderFront:nil];
    c.window.tabbingMode = NSWindowTabbingModePreferred;
    if (url.length) [c loadAddress:url]; else [c showNewTabPage];
    return c;
}

- (BrowserWindowController*)openOblivionWindowWithURL:(NSString*)url {
    BrowserWindowController* c = [self makeController:nil store:[self makeOblivionStore] oblivion:YES];
    c.window.tabbingMode = NSWindowTabbingModeDisallowed;
    [c showWindow:nil];
    [c.window makeKeyAndOrderFront:nil];
    c.window.tabbingMode = NSWindowTabbingModePreferred;
    if (url.length) [c loadAddress:url]; else [c showNewTabPage];
    std::cout << "[lethe] oblivion window opened (isolated in-memory store, https-only, "
                 "tracker protection forced, stealth UA)" << std::endl;
    return c;
}

- (BrowserWindowController*)openTabWithURL:(NSString*)url
                                fromWindow:(NSWindow*)parent
                                   webView:(WKWebView*)existing {
    // A tab born from an Oblivion window stays in Oblivion: same isolated
    // store, same rules. window.open already inherits the configuration.
    BrowserWindowController* parentCtl = nil;
    if ([parent.windowController isKindOfClass:[BrowserWindowController class]])
        parentCtl = (BrowserWindowController*)parent.windowController;
    const BOOL oblivion = parentCtl.oblivion;
    WKWebsiteDataStore* store = oblivion ? parentCtl.dataStore : nil;
    if (!parent) {
        BrowserWindowController* c = [self makeController:existing];
        [c showWindow:nil];
        [c.window makeKeyAndOrderFront:nil];
        if (!existing) { if (url.length) [c loadAddress:url]; else [c showNewTabPage]; }
        return c;
    }
    BrowserWindowController* c = [self makeController:existing store:store oblivion:oblivion];
    [parent addTabbedWindow:c.window ordered:NSWindowAbove];
    [c.window makeKeyAndOrderFront:nil];
    if (!existing) {
        if (url.length) [c loadAddress:url]; else [c showNewTabPage];
    }
    return c;
}

- (void)controllerDidClose:(BrowserWindowController*)controller {
    [controllers_ removeObject:controller];
}

// File > New Tab with no browser window open (responder chain ends here).
- (void)newWindowForTab:(id)sender {
    (void)sender;
    [self openWindowWithURL:nil];
}

- (void)newWindow:(id)sender {
    (void)sender;
    [self openWindowWithURL:nil];
}

- (void)newOblivionWindow:(id)sender {
    (void)sender;
    [self openOblivionWindowWithURL:nil];
}

#pragma mark - Status / privacy actions

- (BOOL)isHttpAllowedForHost:(NSString*)host {
    return host.length && [httpAllowedHosts_ containsObject:host.lowercaseString];
}

- (void)allowHttpForHost:(NSString*)host {
    if (!httpAllowedHosts_) httpAllowedHosts_ = [NSMutableSet set];
    if (host.length) [httpAllowedHosts_ addObject:host.lowercaseString];
}

- (NSString*)securityStatusText {
    const lethe::Config& cfg = ctx_->cfg;
    NSMutableString* s = [NSMutableString string];
    [s appendFormat:@"Lethe v%s\n\n", LETHE_VERSION];
    [s appendFormat:@"Tracker protection: %@\n", trackerRuleCount_
        ? [NSString stringWithFormat:@"on (%lu third-party rules)", (unsigned long)trackerRuleCount_]
        : (ctx_->trackerBlocking ? @"unavailable (rule compile failed)" : @"OFF")];
    NSUInteger oblivionWindows = 0;
    for (BrowserWindowController* c in controllers_) if (c.oblivion) oblivionWindows++;
    [s appendFormat:@"Oblivion windows open: %lu (isolated in-memory store wiped on close, "
                     "https-only, tracker protection forced, stealth UA; ⌘⇧N)\n",
        (unsigned long)oblivionWindows];
    [s appendFormat:@"HTTPS-first: %@\n", ctx_->httpsFirst
        ? [NSString stringWithFormat:@"on (%lu host%@ allowed plain http this session)",
           (unsigned long)httpAllowedHosts_.count, httpAllowedHosts_.count == 1 ? @"" : @"s"]
        : @"OFF"];
    [s appendFormat:@"Secure DNS (DoH): %@\n",
        cfg.dnsProvider.empty() ? @"OFF" : @(cfg.dnsProvider.c_str())];
    [s appendFormat:@"Private-network isolation: %@\n",
        cfg.isolatePrivateNetworks ? @"on (SSRF guard)" : @"OFF"];
    if (ctx_->proxyPort > 0) {
        if (@available(macOS 14.0, *)) {
            [s appendFormat:@"Transport enforcement: policy proxy 127.0.0.1:%d "
                             "(every WebKit request%@)\n", ctx_->proxyPort,
                             ctx_->proxyAuthToken.empty() ? @"" : @", per-launch auth token"];
        } else {
            [s appendString:@"Transport enforcement: navigation gate only "
                             "(macOS 14+ needed for the per-request proxy)\n"];
        }
    } else {
        [s appendString:@"Transport enforcement: navigation gate only\n"];
    }
    const bool vpn = ctx_->engine && ctx_->engine->isVpnConnected();
    [s appendFormat:@"Built-in VPN: %@\n",
        vpn ? @"connected" : (cfg.vpnConfig.endpointHost.empty()
            ? @"not configured" : @"disconnected")];
    [s appendFormat:@"Site data: %@\n",
        ctx_->persistent ? @"persistent" : @"ephemeral (cleared on quit)"];
    [s appendFormat:@"Process sandbox: %@\n",
        cfg.sandboxEnabled ? @"Seatbelt (writes: temp, Downloads, own caches)" : @"OFF"];
    [s appendFormat:@"User agent: %@\n",
        cfg.userAgentMode == "stealth" ? @"stealth (fixed profile)" : @"WebKit default"];
    [s appendString:@"\nInside https, TLS is WebKit's own (system trust); "
                     "Lethe's TLS 1.3 floor, pins and HSTS cover reader-mode "
                     "and proxy hops."];
    return s;
}

- (void)showSecurityStatus:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init];
    a.messageText = @"Security status";
    a.informativeText = [self securityStatusText];
    [a addButtonWithTitle:@"OK"];
    [a runModal];
}

- (void)toggleBookmark:(id)sender {
    (void)sender;
    BrowserWindowController* c = (BrowserWindowController*)[NSApp keyWindow].windowController;
    if (![c isKindOfClass:[BrowserWindowController class]]) {
        for (BrowserWindowController* cw in controllers_) {
            if (cw.window.isVisible) { c = cw; break; }
        }
    }
    if (!c) { NSBeep(); return; }
    [c toggleBookmark:nil];
}

- (void)showBookmarks:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://bookmarks" fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* w = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = w;
        if (strong) [strong renderBookmarksPage];
    });
}

- (void)clearBookmarks:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init]; a.messageText = @"Clear all bookmarks?";
    a.informativeText = @"This removes every saved bookmark.";
    [a addButtonWithTitle:@"Cancel"]; [a addButtonWithTitle:@"Clear"];
    if ([a runModal] == NSAlertSecondButtonReturn) for (LetheBookmark* b in [[LetheBookmarks shared] all]) [[LetheBookmarks shared] removeURL:b.url];
}

- (void)showHistory:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://history" fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* w = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = w;
        if (strong) [strong renderHistoryPage];
    });
}

- (void)clearHistory:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init]; a.messageText = @"Clear browsing history?";
    a.informativeText = @"This removes all recorded visits.";
    [a addButtonWithTitle:@"Cancel"]; [a addButtonWithTitle:@"Clear"];
    if ([a runModal] == NSAlertSecondButtonReturn) [[LetheHistory shared] clear];
}

- (void)showPermissions:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://permissions"
                                          fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* weakC = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = weakC;
        if (strong) [strong renderPermissionsPage];
    });
}

- (void)showPlugins:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://plugins"
                                          fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* weakC = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = weakC;
        if (strong) [strong renderPluginsPage];
    });
}

- (void)clearAllPermissions:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init];
    a.messageText = @"Clear all site permissions?";
    a.informativeText = @"Every site's allow/deny choice will be forgotten. Sites will be asked again.";
    [a addButtonWithTitle:@"Cancel"];
    [a addButtonWithTitle:@"Clear"];
    if ([a runModal] != NSAlertSecondButtonReturn) return;
    [[LethePermissions shared] clearAll];
}

- (void)toggleVpn:(id)sender {
    (void)sender;
    lethe::Engine* engine = ctx_->engine;
    if (!engine) return;
    if (engine->isVpnConnected()) {
        engine->disableVpn();
        return;
    }
    if (ctx_->cfg.vpnConfig.endpointHost.empty()) {
        NSAlert* a = [[NSAlert alloc] init];
        a.messageText = @"No VPN endpoint configured";
        a.informativeText = @"Lethe's built-in WireGuard-style tunnel needs an "
            "endpoint and keys in Config.vpnConfig (see README). Without one, "
            "browsing stays direct; DoH and the private-network guard still apply.";
        [a runModal];
        return;
    }
    if (!engine->enableVpn(ctx_->cfg.vpnConfig)) {
        NSAlert* a = [[NSAlert alloc] init];
        a.messageText = @"VPN handshake failed";
        a.informativeText = @"The endpoint did not complete the handshake. "
            "Traffic is NOT routed through the tunnel.";
        [a runModal];
    }
}

- (void)clearBrowsingData:(id)sender {
    (void)sender;
    WKWebsiteDataStore* store = [self dataStore];
    [store removeDataOfTypes:[WKWebsiteDataStore allWebsiteDataTypes]
               modifiedSince:[NSDate distantPast]
           completionHandler:^{
        std::cout << "[lethe] site data cleared" << std::endl;
    }];
}

- (void)openHelp:(id)sender {
    (void)sender;
    [self openTabWithURL:@"https://github.com/hotocoo/lethe#readme"
              fromWindow:[NSApp keyWindow] webView:nil];
}

- (BOOL)validateMenuItem:(NSMenuItem*)item {
    if (item.action == @selector(toggleVpn:)) {
        const bool on = ctx_->engine && ctx_->engine->isVpnConnected();
        item.title = on ? @"Disconnect VPN" : @"Connect VPN";
    }
    if (item.action == @selector(newOblivionWindow:)) {
        // Oblivion windows are a plugin like everything else: switching the
        // plugin off removes the way in.
        return lethe::PluginRegistry::instance().enabled("oblivion-windows");
    }
    return YES;
}

#pragma mark - Menu bar

static NSMenuItem* addItem(NSMenu* menu, NSString* title, SEL action,
                           NSString* key, NSEventModifierFlags mods) {
    NSMenuItem* it = [[NSMenuItem alloc] initWithTitle:title action:action
                                         keyEquivalent:key];
    it.keyEquivalentModifierMask = mods;
    [menu addItem:it];
    return it;
}

static NSMenu* addSubmenu(NSMenu* bar, NSString* title) {
    NSMenuItem* holder = [[NSMenuItem alloc] initWithTitle:title action:nil
                                             keyEquivalent:@""];
    NSMenu* m = [[NSMenu alloc] initWithTitle:title];
    holder.submenu = m;
    [bar addItem:holder];
    return m;
}


- (void)showPreferences:(id)sender {
    (void)sender;
    // The unified Settings window (sidebar + categories) replaces the old
    // four-checkbox dialog. Cmd+, (Preferences…) is still bound here.
    [[LetheSettings shared] show];
}

- (void)showTabSearch:(id)sender { (void)sender; [[LetheTabSearch shared] show]; }

- (void)prefsToggle:(NSButton*)sender {
    // Legacy: the old preferences dialog used this. The new LetheSettings
    // window writes through [LethePreferences save] directly. Kept as a
    // no-op so the old binary's menu wiring still resolves if a stale
    // .nib is loaded.
    (void)sender;
}

// Apply the current preferences to the running engine. Persistent cookies
// requires a restart (WKWebView's data store is fixed at creation time),
// so we alert the user; everything else is live.
- (void)applyPreferences {
    LethePreferences* prefs = [LethePreferences shared];
    if (ctx_ && ctx_->engine) {
        lethe::MediaUpscalerMode mode = lethe::MediaUpscalerMode::None;
        const char* env = getenv("LETHE_UPSCALER");
        if (env && *env) {
            std::string v = env;
            for (char& ch : v) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
            if (v == "linear") mode = lethe::MediaUpscalerMode::Linear;
            else if (v == "metalfx" || v == "metalfx-spatial" || v == "fsr")
                mode = lethe::MediaUpscalerMode::MetalFX;
        } else if (prefs.upscaler == LetheUpscalerLinear) mode = lethe::MediaUpscalerMode::Linear;
        else if (prefs.upscaler == LetheUpscalerFSR1 || prefs.upscaler == LetheUpscalerDLSSLike)
            mode = lethe::MediaUpscalerMode::MetalFX;
        ctx_->engine->renderer()->setMediaUpscaler(mode);
    }
    // --- Plugins: the registry is the runtime view of every feature ------
    // 1. Mirror the preference-keyed plugins into the registry.
    lethe::PluginRegistry& reg = lethe::PluginRegistry::instance();
    reg.registerBuiltins();
    for (const lethe::PluginSpec& spec : reg.plugins()) {
        if (spec.prefKey.empty()) continue;
        id v = [prefs valueForKey:@(spec.prefKey.c_str())];
        if ([v respondsToSelector:@selector(boolValue)]) {
            reg.setEnabled(spec.id, [v boolValue]);
        }
    }
    // 2. Engine-only plugins (no pref key) live in pluginOverrides.
    for (NSString* k in prefs.pluginOverrides) {
        reg.setEnabled(std::string(k.UTF8String ?: ""),
                       [prefs.pluginOverrides[k] boolValue]);
    }
    // 3. Live-apply what the registry owns (https-first, tracker-block,
    //    stealth-ua, vpn flags) and (re)install the enabled script plugins.
    reg.applyTo(*ctx_);
    [[LethePluginLoader shared] installInto:[self userContentController]];
    // Tracker blocking: remove the currently-installed list (if any) and
    // optionally install a fresh one.
    WKUserContentController* uc = [self userContentController];
    if (trackerRuleList_) {
        [uc removeContentRuleList:trackerRuleList_];
        trackerRuleList_ = nil;
    }
    if (prefs.trackerBlocking) {
        const lethe::TrackerBlocklist& list = lethe::builtinTrackerBlocklist();
        NSString* ident = @(lethe::trackerRulesIdentifier(list).c_str());
        WKContentRuleListStore* store = [WKContentRuleListStore defaultStore];
        [store lookUpContentRuleListForIdentifier:ident
                                completionHandler:^(WKContentRuleList* found, NSError* err) {
            (void)err;
            if (found) {
                [uc addContentRuleList:found];
                self->trackerRuleList_ = found;
                return;
            }
            NSString* json = @(lethe::trackerContentRulesJson(list).c_str());
            [store compileContentRuleListForIdentifier:ident
                                encodedContentRuleList:json
                                     completionHandler:^(WKContentRuleList* compiled, NSError* e) {
                (void)e;
                if (compiled) {
                    [uc addContentRuleList:compiled];
                    self->trackerRuleList_ = compiled;
                }
            }];
        }];
        trackerRuleCount_ = list.domains.size() + list.pathPatterns.size();
    } else {
        trackerRuleCount_ = 0;
    }
    // Stealth UA: push to every existing webView (tab/window).
    NSString* ua = (prefs.stealthUA) ? @(lethe::stealthUserAgentString())
                                     : @"";
    for (BrowserWindowController* c in [controllers_ copy]) {
        if (c.webView) c.webView.customUserAgent = ua.length ? ua : nil;
    }
    // HTTPS-first: the policy gate reads ctx_->httpsFirst; we update it
    // directly. Active navigations already in flight won't roll back.
    ctx_->httpsFirst = prefs.httpsFirst;
    // Persistent cookies: data store is fixed at webView creation time.
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    BOOL want = prefs.persistentCookies;
    if ([defaults boolForKey:@"LETHE_PERSISTENT_HINT"] != want) {
        [defaults setBool:want forKey:@"LETHE_PERSISTENT_HINT"];
    }
    // -- v0.1.1 perf: live perf knobs --------------------------------
    // The user may have set a maxFrameRate or AA via the Settings panel
    // mid-session; push the new values to every existing webView. The
    // policy proxy worker count is fixed at startup (we'd have to drain
    // and re-spawn the pool to change it live), so the Settings UI also
    // tells the user that a relaunch is required for that one knob.
    for (BrowserWindowController* c in [controllers_ copy]) {
        if (!c.webView) continue;
        if (prefs.maxFrameRate > 0) {
            NSLog(@"[lethe] maxFrameRate=%ld (best-effort)", (long)prefs.maxFrameRate);
        }
        // Browser media surfaces are owned by WebKit and are not exposed as
        // Metal textures. The injected WebGL scaler therefore handles the
        // media elements that WebGL is permitted to sample. Mode 1 is the
        // fast linear path; modes 2/3 select the high-quality reconstruction.
        NSInteger mediaMode = 0;
        const char* env = getenv("LETHE_UPSCALER");
        if (env && *env) {
            std::string v = env;
            for (char& ch : v) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
            if (v == "linear") mediaMode = 1;
            else if (v == "metalfx-sharp") mediaMode = 3;
            else if (v == "metalfx" || v == "metalfx-spatial" || v == "fsr") mediaMode = 2;
        } else if (prefs.upscaler == LetheUpscalerLinear) mediaMode = 1;
        else if (prefs.upscaler == LetheUpscalerFSR1) mediaMode = 2;
        else if (prefs.upscaler == LetheUpscalerDLSSLike) mediaMode = 3;
        NSString* js = [NSString stringWithFormat:
            @"window.__letheMediaUpscalerSetMode && window.__letheMediaUpscalerSetMode(%ld);",
            (long)mediaMode];
        [c.webView evaluateJavaScript:js completionHandler:^(id result, NSError* error) {
            (void)result;
            if (error) NSLog(@"[lethe] media upscaler injection: %@", error.localizedDescription);
        }];
    }
}
- (void)buildMenuBar {
    NSMenu* bar = [[NSMenu alloc] init];
    const NSEventModifierFlags cmd = NSEventModifierFlagCommand;
    const NSEventModifierFlags cmdShift = cmd | NSEventModifierFlagShift;
    const NSEventModifierFlags cmdCtrl = cmd | NSEventModifierFlagControl;
    const NSEventModifierFlags ctrl = NSEventModifierFlagControl;

    NSMenu* app = addSubmenu(bar, @"Lethe");
    addItem(app, @"About Lethe", @selector(orderFrontStandardAboutPanel:), @"", 0);
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Security Status…", @selector(showSecurityStatus:), @"i", cmdShift);
    addItem(app, @"Preferences…", @selector(showPreferences:), @",", cmd);
    [app addItem:[NSMenuItem separatorItem]];
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Hide Lethe", @selector(hide:), @"h", cmd);
    addItem(app, @"Hide Others", @selector(hideOtherApplications:), @"h",
            cmd | NSEventModifierFlagOption);
    addItem(app, @"Show All", @selector(unhideAllApplications:), @"", 0);
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Quit Lethe", @selector(terminate:), @"q", cmd);

    NSMenu* file = addSubmenu(bar, @"File");
    addItem(file, @"New Tab", @selector(newWindowForTab:), @"t", cmd);
    addItem(file, @"New Window", @selector(newWindow:), @"n", cmd);
    addItem(file, @"New Oblivion Window", @selector(newOblivionWindow:), @"n", cmdShift);
    addItem(file, @"Open Location…", @selector(focusAddressBar:), @"l", cmd);
    [file addItem:[NSMenuItem separatorItem]];
    addItem(file, @"Close Tab", @selector(performClose:), @"w", cmd);
    addItem(file, @"Close Window", @selector(closeWholeWindow:), @"w", cmdShift);
    [file addItem:[NSMenuItem separatorItem]];
    addItem(file, @"Downloads", @selector(openDownloadsFolder:), @"j", cmdShift);
    addItem(file, @"Reveal Downloads Folder", @selector(revealDownloads:), @"", 0);
    [file addItem:[NSMenuItem separatorItem]];
    addItem(file, @"Print…", @selector(printPage:), @"p", cmd);

    NSMenu* edit = addSubmenu(bar, @"Edit");
    addItem(edit, @"Undo", @selector(undo:), @"z", cmd);
    addItem(edit, @"Redo", @selector(redo:), @"z", cmdShift);
    [edit addItem:[NSMenuItem separatorItem]];
    addItem(edit, @"Cut", @selector(cut:), @"x", cmd);
    addItem(edit, @"Copy", @selector(copy:), @"c", cmd);
    addItem(edit, @"Paste", @selector(paste:), @"v", cmd);
    addItem(edit, @"Select All", @selector(selectAll:), @"a", cmd);
    [edit addItem:[NSMenuItem separatorItem]];
    addItem(edit, @"Find…", @selector(showFindBar:), @"f", cmd);
    addItem(edit, @"Find Next", @selector(findNext:), @"g", cmd);
    addItem(edit, @"Find Previous", @selector(findPrevious:), @"g", cmdShift);

    NSMenu* bookmarks = addSubmenu(bar, @"Bookmarks");
    addItem(bookmarks, @"Toggle Bookmark", @selector(toggleBookmark:), @"d", cmd);
    addItem(bookmarks, @"Show All Bookmarks…", @selector(showBookmarks:), @"", 0);
    [bookmarks addItem:[NSMenuItem separatorItem]];
    addItem(bookmarks, @"Clear Bookmarks", @selector(clearBookmarks:), @"", 0);

    NSMenu* view = addSubmenu(bar, @"View");
    addItem(view, @"Reload Page", @selector(reloadPage:), @"r", cmd);
    addItem(view, @"Stop", @selector(stopLoading:), @".", cmd);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Reader View", @selector(toggleReader:), @"r", cmdShift);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Find in Tabs…", @selector(showTabSearch:), @"\\", cmd);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Show Web Inspector", @selector(showWebInspector:), @"i", cmd | NSEventModifierFlagOption);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Actual Size", @selector(zoomActual:), @"0", cmd);
    addItem(view, @"Zoom In", @selector(zoomIn:), @"=", cmd);
    addItem(view, @"Zoom Out", @selector(zoomOut:), @"-", cmd);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Enter Full Screen", @selector(toggleFullScreen:), @"f", cmdCtrl);

    NSMenu* history = addSubmenu(bar, @"History");
    addItem(history, @"Back", @selector(goBack:), @"[", cmd);
    addItem(history, @"Forward", @selector(goForward:), @"]", cmd);
    [history addItem:[NSMenuItem separatorItem]];
    addItem(history, @"Home", @selector(goHome:), @"h", cmdShift);
    [history addItem:[NSMenuItem separatorItem]];
    addItem(history, @"Show All History…", @selector(showHistory:), @"y", cmd);
    addItem(history, @"Clear History", @selector(clearHistory:), @"", 0);

    NSMenu* privacy = addSubmenu(bar, @"Privacy");
    addItem(privacy, @"Connect VPN", @selector(toggleVpn:), @"", 0);
    addItem(privacy, @"Clear Browsing Data", @selector(clearBrowsingData:), @"", 0);
    [privacy addItem:[NSMenuItem separatorItem]];
    addItem(privacy, @"Site Permissions…", @selector(showPermissions:), @"", 0);
    addItem(privacy, @"Clear All Permissions", @selector(clearAllPermissions:), @"", 0);
    [privacy addItem:[NSMenuItem separatorItem]];
    addItem(privacy, @"Plugins…", @selector(showPlugins:), @"", 0);
    addItem(privacy, @"Security Status…", @selector(showSecurityStatus:), @"", 0);

    NSMenu* window = addSubmenu(bar, @"Window");
    addItem(window, @"Minimize", @selector(performMiniaturize:), @"m", cmd);
    addItem(window, @"Zoom", @selector(performZoom:), @"", 0);
    [window addItem:[NSMenuItem separatorItem]];
    addItem(window, @"Show Previous Tab", @selector(selectPreviousTab:), @"\t",
            ctrl | NSEventModifierFlagShift);
    addItem(window, @"Show Next Tab", @selector(selectNextTab:), @"\t", ctrl);
    addItem(window, @"Move Tab to New Window", @selector(moveTabToNewWindow:), @"", 0);
    addItem(window, @"Merge All Windows", @selector(mergeAllWindows:), @"", 0);
    [window addItem:[NSMenuItem separatorItem]];
    addItem(window, @"Bring All to Front", @selector(arrangeInFront:), @"", 0);
    [NSApp setWindowsMenu:window];

    NSMenu* help = addSubmenu(bar, @"Help");
    addItem(help, @"Lethe Help", @selector(openHelp:), @"?", cmd);
    [NSApp setHelpMenu:help];

    [NSApp setMainMenu:bar];
}

@end
