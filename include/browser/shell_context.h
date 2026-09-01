// shell_context.h - what every native shell (AppKit+CEF, AppKit+WKWebView,
// GTK+WebKitGTK) receives from the bootstrap: the engine, TLS config, the
// local policy proxy binding and the user's launch options.
#ifndef LETHE_BROWSER_SHELL_CONTEXT_H
#define LETHE_BROWSER_SHELL_CONTEXT_H

#include <functional>
#include <memory>
#include <string>

#include "core/engine.h"
#include "network/doh_resolver.h"
#include "network/http_client.h"
#include "network/tls_config.h"

namespace lethe {

struct ShellContext {
    Engine* engine = nullptr;
    Config cfg;
    TLSConfig tls;
    int proxyPort = 0;            // local PolicyProxyServer port (0 = none)
    std::string proxyAuthToken;   // per-launch secret the engine presents to the proxy
    bool httpsFirst = true;       // upgrade top-level http:// to https:// first
    bool trackerBlocking = true;  // built-in third-party tracker rules
    std::shared_ptr<SharedDohCache> dohCache;        // shared by gate, reader, proxy
    std::shared_ptr<SharedDohResolver> dohResolver;  // keep-alive pool, same sharing
    std::shared_ptr<PersistentDohCache> persistentDohCache;  // disk-backed, survives restarts
    bool persistent = false;      // false = ephemeral (incognito) data store
    std::string homeUrl;          // "" = built-in new-tab page
    std::function<void()> onTerminate;  // engine/proxy shutdown
    std::string e2eScript;        // --e2e-script <file>: drive + assert, then exit
};

} // namespace lethe

#endif // LETHE_BROWSER_SHELL_CONTEXT_H
