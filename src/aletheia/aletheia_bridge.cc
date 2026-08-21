// aletheia_bridge.cc — Aletheia OS integration for Lethe
//
// Implements the bridge that integrates Lethe as the native browser of the
// Aletheia OS and gives its LLM agent web access through Lethe's secure
// network stack.

#include "aletheia/aletheia_bridge.h"
#include <iostream>

namespace lethe {
namespace aletheia {

AletheiaBridge::AletheiaBridge(Engine* engine) : engine_(engine) {
    if (engine_) {
        // Initialize the LLM search service with the engine's HTTP client
        // and VPN tunnel.
        llm::SearchConfig searchCfg;
        searchCfg.useVpn = true;
        searchService_ = std::make_unique<llm::SearchService>();
        searchInitialized_ = searchService_->initialize(
            engine_->httpClient(), engine_->vpnTunnel(), searchCfg);
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
    std::cout << "[aletheia] Opened URL: " << url << " (tab " << tabId << ")" << std::endl;
    return true;
}

bool AletheiaBridge::navigate(const std::string& url) {
    if (!engine_ || !engine_->tabManager()) return false;
    int tabId = engine_->tabManager()->getActiveTab();
    if (tabId <= 0) return false;
    engine_->tabManager()->navigate(tabId, url);
    return true;
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
    std::string url = getCurrentUrl();
    if (url.empty()) return "";

    // Use the search service to read the page content.
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

