// aletheia_bridge.cc — Aletheia OS integration for Lethe
//
// Implements the bridge that integrates Lethe as the native browser of the
// Aletheia OS and gives its LLM agent web access through Lethe's secure
// network stack.

#include "aletheia/aletheia_bridge.h"
#include <iostream>

namespace lethe {
namespace aletheia {

AletheiaBridge::AletheiaBridge(Engine* engine,
                               const llm::SearchConfig& searchConfig)
    : engine_(engine) {
    if (engine_) {
        // Initialize the LLM search service with the engine's HTTP client
        // and VPN tunnel. All LLM traffic therefore inherits the engine's
        // policies: DoH resolution, VPN fail-closed routing, TLS policy.
        llm::SearchConfig cfg = searchConfig;
        cfg.useVpn = true;
        searchService_ = std::make_unique<llm::SearchService>();
        searchInitialized_ = searchService_->initialize(
            engine_->httpClient(), engine_->vpnTunnel(), cfg);
        if (searchInitialized_) {
            std::cout << "[aletheia] Lethe bridge initialized with LLM search" << std::endl;
        }
    }
}

AletheiaBridge::~AletheiaBridge() = default;

// --- Native browser control ---

bool AletheiaBridge::openUrl(const std::string& url, bool newTab) {
    if (!engine_ || !engine_->tabManager()) return false;

    auto* tabs = engine_->tabManager();
    int tabId;
    if (newTab) {
        tabId = tabs->createTab("New Tab", url);
        tabs->setActiveTab(tabId);
    } else {
        tabId = tabs->getActiveTab();
        if (tabId <= 0) {
            tabId = tabs->createTab("New Tab", url);
            tabs->setActiveTab(tabId);
        }
    }

    tabs->navigate(tabId, url);
    // Real navigation: fetch the document through the engine's secure stack
    // (DoH resolution + VPN fail-closed policy) so the OS sees an actually
    // loaded page - title, readable text - not just a recorded intent.
    loadActiveTab(url);
    std::cout << "[aletheia] Opened URL: " << url
              << (pageLoaded_ ? " (loaded)" : " (load blocked)")
              << " (tab " << tabId << ")" << std::endl;
    return true;
}

bool AletheiaBridge::navigate(const std::string& url) {
    if (!engine_ || !engine_->tabManager()) return false;
    int tabId = engine_->tabManager()->getActiveTab();
    if (tabId <= 0) return false;
    engine_->tabManager()->navigate(tabId, url);
    loadActiveTab(url);
    return true;
}

bool AletheiaBridge::loadActiveTab(const std::string& url) {
    pageLoaded_ = false;
    loadedUrl_.clear();
    loadedText_.clear();

    auto* tabs = engine_ ? engine_->tabManager() : nullptr;
    if (!tabs) return false;
    const int tabId = tabs->getActiveTab();

    if (!searchService_ || !searchInitialized_) {
        if (tabId > 0) tabs->setTabLoading(tabId, false);
        return false;
    }

    if (tabId > 0) tabs->setTabLoading(tabId, true);

    llm::PageContent content = searchService_->readPage(url);
    if (tabId > 0) tabs->setTabLoading(tabId, false);

    if (!content.success) {
        // Fail closed: the tab keeps its previous title and serves no text.
        std::cerr << "[aletheia] Navigation blocked or failed: "
                  << content.error << std::endl;
        return false;
    }

    const std::string finalUrl =
        content.url.empty() ? url : content.url;
    const std::string title =
        content.title.empty() ? finalUrl : content.title;

    if (tabId > 0) tabs->setTabTitle(tabId, title);

    loadedUrl_ = finalUrl;
    loadedText_ = content.textContent;
    pageLoaded_ = true;

    // History records real visits only, and never in incognito sessions.
    if (!engine_->config().incognitoMode && engine_->history()) {
        engine_->history()->addEntry(finalUrl, title);
    }

    return true;
}

bool AletheiaBridge::currentPageLoaded() const {
    return pageLoaded_ && loadedUrl_ == getCurrentUrl();
}

std::string AletheiaBridge::getCurrentUrl() const {
    if (!engine_ || !engine_->tabManager()) return "";
    int tabId = engine_->tabManager()->getActiveTab();
    const auto* info = engine_->tabManager()->getTabInfo(tabId);
    return info ? info->url : "";
}

std::string AletheiaBridge::getCurrentTitle() const {
    if (!engine_ || !engine_->tabManager()) return "";
    int tabId = engine_->tabManager()->getActiveTab();
    const auto* info = engine_->tabManager()->getTabInfo(tabId);
    return info ? info->title : "";
}

std::string AletheiaBridge::getCurrentPageContent() {
    if (!engine_ || !engine_->tabManager()) return "";
    const std::string url = getCurrentUrl();
    if (url.empty()) return "";

    // Serve the reader text of the already-loaded document when it belongs
    // to this URL: no duplicate fetch for repeated OS reads.
    if (pageLoaded_ && loadedUrl_ == url) return loadedText_;

    // Fall back to a live read (e.g. URL set outside this bridge).
    if (searchService_ && searchInitialized_) {
        auto content = searchService_->readPage(url);
        return content.textContent;
    }
    return "";
}

BrowserStatus AletheiaBridge::getStatus() const {
    BrowserStatus status;
    if (!engine_) return status;

    // Status polling doubles as the VPN maintenance driver: rekey, retry,
    // and keepalive happen here so the OS never sees a stale session.
    engine_->pumpVpnMaintenance();

    status.running = engine_->isRunning();
    status.vpnConnected = engine_->isVpnConnected();
    status.currentUrl = getCurrentUrl();
    status.currentTitle = getCurrentTitle();
    status.pageLoaded = currentPageLoaded();

    if (engine_->tabManager()) {
        status.activeTabId = engine_->tabManager()->getActiveTab();
        status.tabCount = engine_->tabManager()->count();
    }

    return status;
}

// --- Built-in VPN control ---

bool AletheiaBridge::enableVpn(const vpn::VpnConfig& config) {
    if (!engine_) return false;
    bool ok = engine_->enableVpn(config);
    if (ok) {
        std::cout << "[aletheia] Built-in VPN enabled" << std::endl;
    }
    return ok;
}

bool AletheiaBridge::disableVpn() {
    if (!engine_) return false;
    return engine_->disableVpn();
}

bool AletheiaBridge::isVpnConnected() const {
    return engine_ && engine_->isVpnConnected();
}

// --- LLM search integration ---

std::vector<llm::SearchResult> AletheiaBridge::llmWebSearch(const std::string& query) {
    if (!searchService_ || !searchInitialized_) {
        std::cerr << "[aletheia] LLM search not available" << std::endl;
        return {};
    }
    return searchService_->webSearch(query);
}

llm::PageContent AletheiaBridge::llmReadPage(const std::string& url) {
    if (!searchService_ || !searchInitialized_) {
        llm::PageContent empty;
        empty.error = "LLM search not available";
        return empty;
    }
    return searchService_->readPage(url);
}

llm::PageContent AletheiaBridge::llmSearchAndRead(const std::string& query) {
    if (!searchService_ || !searchInitialized_) {
        llm::PageContent empty;
        empty.error = "LLM search not available";
        return empty;
    }
    return searchService_->searchAndRead(query);
}

bool AletheiaBridge::isLlmSearchUsingVpn() const {
    return searchService_ && searchService_->isUsingVpn();
}

} // namespace aletheia
} // namespace lethe

