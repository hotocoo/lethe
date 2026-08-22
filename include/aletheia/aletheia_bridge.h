#ifndef LETHE_ALETHEIA_ALETHEIA_BRIDGE_H
#define LETHE_ALETHEIA_ALETHEIA_BRIDGE_H

// aletheia_bridge.h — Aletheia OS integration for Lethe
//
// This is the bridge that integrates Lethe as the native browser of the
// Aletheia OS. It exposes a unified API for:
//   - Native browser control (open, navigate, read content)
//   - Built-in VPN control (enable, disable, status)
//   - LLM search integration (the OS LLM uses Lethe for web search)
//
// The Aletheia OS calls this bridge to interact with the browser and to give
// its LLM agent web access through Lethe's secure, private network stack.

#include <map>
#include <string>
#include <vector>
#include <memory>
#include "core/engine.h"
#include "llm/search_service.h"
#include "network/vpn/vpn_config.h"
#include "network/vpn/vpn_tunnel.h"

namespace lethe {
namespace aletheia {

// Status of the Lethe browser as seen by the Aletheia OS.
struct BrowserStatus {
    bool running = false;
    bool vpnConnected = false;
    std::string currentUrl;
    std::string currentTitle;
    int activeTabId = 0;
    size_t tabCount = 0;
    // Whether the active tab's current URL was fetched successfully through
    // Lethe's secure network stack (DoH resolution, VPN fail-closed policy).
    bool pageLoaded = false;
};

// The Aletheia OS bridge for Lethe.
class AletheiaBridge {
public:
    // searchConfig overrides the default LLM search settings (engine URL,
    // timeouts, VPN preference). The default targets the built-in
    // Aletheia search endpoint.
    explicit AletheiaBridge(Engine* engine,
                            const llm::SearchConfig& searchConfig = {});
    ~AletheiaBridge();

    // --- Native browser control ---
    // Open a URL in a new tab (or the active tab).
    bool openUrl(const std::string& url, bool newTab = false);

    // Navigate the active tab to a URL.
    bool navigate(const std::string& url);

    // Get the current URL of the active tab.
    std::string getCurrentUrl() const;

    // Get the current page title.
    std::string getCurrentTitle() const;

    // Get the readable content of the current page (for the OS / LLM).
    // Served from the loaded page when current; re-reads otherwise.
    std::string getCurrentPageContent();

    // Whether the active tab's current URL was fetched successfully through
    // Lethe's secure stack. A blocked navigation (e.g. VPN tunnel down under
    // a full-tunnel policy) leaves this false - nothing loaded, nothing leaked.
    bool currentPageLoaded() const;

    // --- Session history ---
    bool canGoBack() const;
    bool canGoForward() const;

    // Traverse session history using the full secure-stack load pipeline
    // (DoH + VPN fail-closed policy). The history cursor moves only when
    // the target actually loads: a blocked or failed traversal leaves
    // history and tab state untouched. Nothing is re-recorded by traversal,
    // and going back never bypasses the security policy - it refetches.
    bool goBack();
    bool goForward();

    // Get the browser status.
    BrowserStatus getStatus() const;

    // --- Built-in VPN control ---
    // Enable the built-in VPN with the given config.
    bool enableVpn(const vpn::VpnConfig& config);

    // Disable the built-in VPN.
    bool disableVpn();

    // Check if the VPN is connected.
    bool isVpnConnected() const;

    // --- LLM search integration ---
    // The OS LLM calls this to perform web searches through Lethe.
    std::vector<llm::SearchResult> llmWebSearch(const std::string& query);

    // The OS LLM calls this to read a page through Lethe.
    llm::PageContent llmReadPage(const std::string& url);

    // The OS LLM calls this to search and read the top result.
    llm::PageContent llmSearchAndRead(const std::string& query);

    // Whether the LLM search is using the VPN.
    bool isLlmSearchUsingVpn() const;

private:
    // Fetch the given URL for the active tab through the engine's secure
    // stack (DoH + VPN fail-closed policy). On success publishes the document
    // title to the tab, caches the readable text, and records history when
    // recordHistory is set and the session is not incognito. On failure
    // clears the cached page: a blocked navigation serves nothing.
    bool loadActiveTab(const std::string& url, bool recordHistory = true);

    // Shared implementation of goBack()/goForward().
    bool traverseHistory(bool forward);

    Engine* engine_;
    std::unique_ptr<llm::SearchService> searchService_;
    bool searchInitialized_ = false;

    // Reader text of the last successful load, per tab. After a blocked or
    // failed navigation the entry stays, but getCurrentPageContent() serves
    // it only while the tab still addresses exactly that URL.
    struct LoadedPage {
        std::string url;
        std::string text;
    };
    std::map<int, LoadedPage> tabPages_;

    // Drop cache entries for tabs that no longer exist.
    void pruneTabPages();
};

} // namespace aletheia
} // namespace lethe

#endif // LETHE_ALETHEIA_ALETHEIA_BRIDGE_H

