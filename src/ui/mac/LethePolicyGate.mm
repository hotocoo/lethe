// LethePolicyGate.mm - navigation policy + reader fetches via lethe_core
//
// HttpClient is single-threaded; each client here is confined to its own
// serial queue. Policy checks (DoH round-trip) never run on the main
// thread, so a slow resolver cannot freeze the UI.

#import "ui/mac/LetheShell.h"

#include <memory>
#include <string>

#include "renderer/html_view.h"
#include "renderer/page_templates.h"

@interface LethePolicyGate () {
    dispatch_queue_t policyQueue_;
    dispatch_queue_t readerQueue_;
    std::unique_ptr<lethe::HttpClient> checker_;
    std::unique_ptr<lethe::HttpClient> reader_;
}
@end

@implementation LethePolicyGate

static std::unique_ptr<lethe::HttpClient> makeClient(const lethe::ShellContext& ctx) {
    auto c = std::make_unique<lethe::HttpClient>();
    c->initialize(ctx.tls);
    if (!ctx.cfg.dnsProvider.empty()) c->setDohProvider(ctx.cfg.dnsProvider);
    lethe::PrivateNetworkPolicy pn;
    pn.isolatePrivateNetworks = ctx.cfg.isolatePrivateNetworks;
    for (const auto& h : ctx.cfg.privateNetworkAllowedHosts) pn.allowedHosts.insert(h);
    c->setPrivateNetworkPolicy(pn);
    if (ctx.engine && ctx.engine->vpnTunnel()) {
        // Non-owning: the engine owns the tunnel for the process lifetime.
        c->setVpnTunnel(std::shared_ptr<lethe::vpn::VpnTunnel>(
            ctx.engine->vpnTunnel(), [](lethe::vpn::VpnTunnel*) {}));
    }
    return c;
}

- (instancetype)initWithContext:(const lethe::ShellContext&)ctx {
    if ((self = [super init])) {
        policyQueue_ = dispatch_queue_create("org.aletheia.lethe.policy",
                                             DISPATCH_QUEUE_SERIAL);
        readerQueue_ = dispatch_queue_create("org.aletheia.lethe.reader",
                                             DISPATCH_QUEUE_SERIAL);
        checker_ = makeClient(ctx);
        reader_ = makeClient(ctx);
    }
    return self;
}

- (void)checkURL:(NSString*)url completion:(void (^)(NSString*))completion {
    std::string target = url.UTF8String ? url.UTF8String : "";
    lethe::HttpClient* checker = checker_.get();
    dispatch_async(policyQueue_, ^{
        std::string reason = checker->policyCheckUrl(target);
        NSString* out = @(reason.c_str());
        dispatch_async(dispatch_get_main_queue(), ^{ completion(out); });
    });
}

- (void)fetchReaderForURL:(NSString*)url
               completion:(void (^)(NSString*, NSString*, NSString*))completion {
    std::string target = url.UTF8String ? url.UTF8String : "";
    lethe::HttpClient* client = reader_.get();
    dispatch_async(readerQueue_, ^{
        lethe::HttpRequest req;
        req.url = target;
        req.method = lethe::HttpMethod::GET;
        req.navigationRequest = true;
        lethe::HttpResponse resp = client->sendRequest(req);
        NSString* html = nil;
        NSString* finalUrl = nil;
        NSString* error = nil;
        if (resp.success && resp.statusCode >= 200 && resp.statusCode < 300) {
            const std::string body(resp.body.begin(), resp.body.end());
            const std::string src = resp.finalUrl.empty() ? target : resp.finalUrl;
            const std::string page =
                lethe::renderReaderPage(src, lethe::HtmlView::extractBlocks(body));
            html = [[NSString alloc] initWithBytes:page.data() length:page.size()
                                          encoding:NSUTF8StringEncoding];
            if (!html) {
                // Not valid UTF-8 (mislabelled legacy page): decode as Latin-1
                // so the reader still shows text instead of failing.
                html = [[NSString alloc] initWithBytes:page.data() length:page.size()
                                              encoding:NSISOLatin1StringEncoding];
            }
            finalUrl = @(src.c_str()) ?: url;
        } else if (resp.success) {
            error = [NSString stringWithFormat:@"HTTP %d", resp.statusCode];
        } else {
            error = @(resp.error.empty() ? "request failed" : resp.error.c_str()) ?: @"request failed";
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(html, finalUrl, error);
        });
    });
}

@end
