// aletheia_bridge.cc — Aletheia OS integration for Lethe
//
// Implements the bridge that integrates Lethe as the native browser of the
// Aletheia OS and gives its LLM agent web access through Lethe's secure
// network stack.

#include "aletheia/aletheia_bridge.h"
#include <algorithm>
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
    const bool loaded = loadActiveTab(url);
    std::cout << "[aletheia] Opened URL: " << url
              << (loaded ? " (loaded)" : " (load blocked)")
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

bool AletheiaBridge::loadActiveTab(const std::string& url, bool recordHistory) {
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

    if (!content.success || tabId <= 0) {
        // Fail closed WITHOUT wiping the tab's previous document: the
        // URL-match guard in getCurrentPageContent() only serves text whose
        // URL equals the tab's address, so a blocked navigation to B never
        // leaks or serves A's text - and restoring the tab to A (history
        // traversal) keeps working offline-from-cache.
        if (!content.success) {
            std::cerr << "[aletheia] Navigation blocked or failed: "
                      << content.error << std::endl;
        }
        return false;
    }

    const std::string finalUrl =
        content.url.empty() ? url : content.url;
    const std::string title =
        content.title.empty() ? finalUrl : content.title;

    tabs->setTabTitle(tabId, title);
    // A redirect moved the document: the tab now shows the final URL, so
    // later reads and status polls address the right resource.
    if (finalUrl != url) tabs->setTabUrl(tabId, finalUrl);

    tabPages_[tabId] = LoadedPage{finalUrl, content.textContent};

    // History records real visits only (never back/forward traversal),
    // and never in incognito sessions. Each tab keeps its own history.
    auto* tabHist = tabs->history(tabId);
    if (recordHistory && !engine_->config().incognitoMode && tabHist) {
        tabHist->addEntry(finalUrl, title);
    }

    return true;
}

void AletheiaBridge::pruneTabPages() {
    if (!engine_ || !engine_->tabManager()) {
        tabPages_.clear();
        return;
    }
    const auto ids = engine_->tabManager()->getAllTabIds();
    for (auto it = tabPages_.begin(); it != tabPages_.end();) {
        if (std::find(ids.begin(), ids.end(), it->first) == ids.end()) {
            it = tabPages_.erase(it);
        } else {
            ++it;
        }
    }
}

bool AletheiaBridge::currentPageLoaded() const {
    if (!engine_ || !engine_->tabManager()) return false;
    const int tabId = engine_->tabManager()->getActiveTab();
    const auto it = tabPages_.find(tabId);
    return it != tabPages_.end() && it->second.url == getCurrentUrl();
}

// --- Session history ---
//
// Every traversal and recording below uses the ACTIVE TAB's own history:
// going back in one tab can never land it on another tab's page.

bool AletheiaBridge::canGoBack() const {
    if (!engine_ || !engine_->tabManager()) return false;
    const int tabId = engine_->tabManager()->getActiveTab();
    const auto* h = engine_->tabManager()->history(tabId);
    return h && h->canGoBack();
}

bool AletheiaBridge::canGoForward() const {
    if (!engine_ || !engine_->tabManager()) return false;
    const int tabId = engine_->tabManager()->getActiveTab();
    const auto* h = engine_->tabManager()->history(tabId);
    return h && h->canGoForward();
}

bool AletheiaBridge::traverseHistory(bool forward) {
    if (!engine_ || !engine_->tabManager()) return false;
    auto* tabs = engine_->tabManager();
    const int tabId = tabs->getActiveTab();
    auto* hist = tabId > 0 ? tabs->history(tabId) : nullptr;
    if (!hist) return false;

    // Peek without committing: the cursor moves only if the target loads.
    const auto* target = forward ? hist->peekForward() : hist->peekBack();
    if (!target) return false;

    // Copy before any load can mutate history (redirects re-record nothing
    // here, but defensive copies keep the traversal atomic).
    const std::string url = target->url;

    tabs->navigate(tabId, url);
    if (!loadActiveTab(url, /*recordHistory=*/false)) {
        // Fail closed: restore the tab to the entry the session sits on.
        const auto* cur = hist->current();
        if (cur) {
            tabs->setTabUrl(tabId, cur->url);
            if (!cur->title.empty()) tabs->setTabTitle(tabId, cur->title);
        }
        return false;
    }

    // The load really happened: commit the cursor move. Traversal itself is
    // never recorded as a new visit.
    if (forward) {
        (void)hist->goForward();
    } else {
        (void)hist->goBack();
    }
    return true;
}

bool AletheiaBridge::goBack() { return traverseHistory(false); }

bool AletheiaBridge::goForward() { return traverseHistory(true); }

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
    pruneTabPages();

    const int tabId = engine_->tabManager()->getActiveTab();
    const std::string url = getCurrentUrl();
    if (url.empty()) return "";

    // Serve the reader text already held for THIS tab when it matches:
    // no duplicate fetch for repeated OS reads, independent per tab.
    const auto it = tabPages_.find(tabId);
    if (it != tabPages_.end() && it->second.url == url) {
        return it->second.text;
    }

    // Fall back to a live read (URL set outside this bridge, or a tab
    // switch to a page not yet cached here) and remember what came back.
    if (searchService_ && searchInitialized_) {
        auto content = searchService_->readPage(url);
        if (!content.success) return "";
        const std::string finalUrl =
            content.url.empty() ? url : content.url;
        tabPages_[tabId] = LoadedPage{finalUrl, content.textContent};
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

