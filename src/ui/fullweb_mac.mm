// fullweb_mac.mm - WKWebView backend of Lethe full-web mode.
//
// The system WebKit renders the page (JavaScript, CSS, H.264/AVC video via
// AVFoundation - YouTube works). Every navigation passes
// HttpClient::policyCheckUrl() first: DoH-only resolution, private-network
// guard on the RESOLVED address, VPN fail-closed routing. Refusals cancel
// the load and surface a named block page instead of hanging silently.
//
// Raster scaling: layer.contentsScale = scale * display backingScale.
//   0.66-0.85 -> FSR-style: fewer raster pixels, compositor upscale
//   1.25-2.00 -> DLAA-style supersampling: extra pixels, downscale AA

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import <WebKit/WKNavigationDelegate.h>
#import <WebKit/WKWebView.h>

#include "ui/fullweb.h"

namespace lethe {

struct FullWebWindow::Impl {
    NSWindow* window = nil;
    WKWebView* web = nil;
    id<WKNavigationDelegate> delegate = nil;
};

} // namespace lethe

@interface LetheNavGate : NSObject <WKNavigationDelegate>
@property (nonatomic, assign) lethe::HttpClient* checker;
@end

@implementation LetheNavGate
- (void)webView:(WKWebView*)webView
    decidePolicyForNavigationAction:(WKNavigationAction*)action
                    decisionHandler:(void (^)(WKNavigationActionPolicy))handler {
    (void)webView;
    NSURL* url = action.request.URL;
    if (!url.absoluteString) {
        handler(WKNavigationActionPolicyCancel);
        return;
    }
    std::string target(url.absoluteString.UTF8String ? "" : "");
    const char* abs = url.absoluteString.UTF8String;
    target = abs ? std::string(abs) : std::string();
    std::string reason = _checker ? _checker->policyCheckUrl(target) : std::string();
    if (!reason.empty()) {
        NSLog(@"[lethe-fullweb] refused %s: %s", target.c_str(), reason.c_str());
        NSString* html = [NSString stringWithFormat:
            @"<html><body style=\"font-family:sans-serif;background:#111;color:#eee;padding:2em\">"
            @"<h2>Blocked by Lethe policy</h2><p>%s</p></body></html>", reason.c_str()];
        [webView loadHTMLString:html baseURL:nil];
        handler(WKNavigationActionPolicyCancel);
        return;
    }
    handler(WKNavigationActionPolicyAllow);
}
@end

namespace lethe {

FullWebWindow::FullWebWindow(FullWebConfig cfg) : cfg_(cfg) {
    policyChecker_ = std::make_unique<HttpClient>();
    policyChecker_->initialize(cfg_.tls);
    if (!cfg_.dohProvider.empty()) policyChecker_->setDohProvider(cfg_.dohProvider);
    policyChecker_->setPrivateNetworkPolicy(cfg_.privateNet);
    if (cfg_.vpnTunnel) policyChecker_->setVpnTunnel(
        std::shared_ptr<vpn::VpnTunnel>(cfg_.vpnTunnel, [](vpn::VpnTunnel*) {}));
}

FullWebWindow::~FullWebWindow() = default;

static void applyRasterScale(WKWebView* web, double scale) {
    if (!web) return;
    CGFloat backing = web.window.screen.backingScaleFactor;
    if (backing <= 0) backing = [[NSScreen mainScreen] backingScaleFactor];
    web.wantsLayer = YES;
    web.layer.contentsScale = static_cast<CGFloat>(scale) * backing;
}

bool FullWebWindow::open(const std::string& url, std::string& error) {
    @autoreleasepool {
        if (!NSApp) [NSApplication sharedApplication];
        [NSApp activateIgnoringOtherApps:YES];

        if (!impl_) impl_ = std::make_unique<Impl>();
        if (!impl_->window) {
            impl_->delegate = [[LetheNavGate alloc] init];
            static_cast<LetheNavGate*>(impl_->delegate).checker = policyChecker_.get();

            WKWebViewConfiguration* cfg = [[WKWebViewConfiguration alloc] init];
            if (cfg_.incognito)
                cfg.websiteDataStore = [WKWebsiteDataStore nonPersistentDataStore];
            CGRect frame = NSMakeRect(0, 0, 1180, 800);
            impl_->web = [[WKWebView alloc] initWithFrame:frame configuration:cfg];
            impl_->web.navigationDelegate = impl_->delegate;
            impl_->web.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

            impl_->window = [[NSWindow alloc]
                initWithContentRect:frame
                          styleMask:NSWindowStyleMaskTitled |
                                    NSWindowStyleMaskClosable |
                                    NSWindowStyleMaskResizable
                            backing:NSBackingStoreBuffered
                              defer:NO];
            impl_->window.title = @"Lethe - Full Web";
            impl_->window.contentView = impl_->web;
            [impl_->window center];
            [impl_->window makeKeyAndOrderFront:nil];
        }
        applyRasterScale(impl_->web, cfg_.rasterScale);

        NSURLRequest* req = [NSURLRequest requestWithURL:[NSURL URLWithString:@(url.c_str())]];
        if (!req.URL) {
            error = "invalid URL for full-web mode: " + url;
            return false;
        }
        [impl_->web loadRequest:req];
        return true;
    }
}

void FullWebWindow::setRasterScale(double scale) {
    cfg_.rasterScale = scale;
    @autoreleasepool {
        applyRasterScale(impl_ ? impl_->web : nil, scale);
    }
}

} // namespace lethe
