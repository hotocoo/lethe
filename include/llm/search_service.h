#ifndef LETHE_LLM_SEARCH_SERVICE_H
#define LETHE_LLM_SEARCH_SERVICE_H

// search_service.h — LLM search integration for Lethe
//
// This is the API that the Aletheia OS LLM uses to perform web searches and
// read pages through the Lethe browser's network stack. The LLM calls
// webSearch() to get structured results and readPage() to get readable
// content, both of which can be routed through the built-in VPN for privacy.
//
// No telemetry, no tracking. All requests go through Lethe's secure network
// stack with TLS 1.3+ and optional VPN encryption.

#include <string>
#include <vector>
#include <memory>
#include "network/http_client.h"
#include "network/vpn/vpn_tunnel.h"

namespace lethe {
namespace llm {

// A single search result returned to the LLM.
struct SearchResult {
    int position;          // 1-based rank
    std::string title;     // Page title
    std::string url;       // Page URL
    std::string snippet;   // Short description / snippet
    double relevanceScore; // 0.0 - 1.0 relevance estimate
};

// A fully-read page returned to the LLM.
struct PageContent {
    bool success = false;
    std::string url;         // Final URL (after redirects)
    std::string title;       // Page title
    std::string textContent; // Extracted readable text
    int statusCode = 0;      // HTTP status code
    bool viaVpn = false;     // Whether this was fetched through the VPN
    std::string error;       // Error message if success is false
};

// Configuration for the search service.
struct SearchConfig {
    std::string searchEngineUrl = "https://search.aletheia.os"; // Built-in search
    std::string userAgent = "Lethe/1.0 (Aletheia OS LLM Agent)";
    int maxResults = 10;         // Max results per search
    int requestTimeoutSec = 15;  // Per-request timeout
    bool useVpn = true;          // Route search through built-in VPN
    bool extractReadableText = true; // Strip HTML to readable text
};

// The search service used by the Aletheia OS LLM.
class SearchService {
public:
    SearchService();
    ~SearchService();

    // Initialize with the browser's HTTP client and optional VPN tunnel.
    bool initialize(HttpClient* httpClient, vpn::VpnTunnel* vpnTunnel = nullptr,
                    const SearchConfig& config = {});

    // Perform a web search and return structured results for the LLM.
    std::vector<SearchResult> webSearch(const std::string& query);

    // Read a page and return its readable content for the LLM.
    PageContent readPage(const std::string& url);

    // Perform a search and read the top result (convenience for the LLM).
    PageContent searchAndRead(const std::string& query);

    // Whether the search service is using the VPN.
    bool isUsingVpn() const;

    // Whether the search service is properly initialized.
    bool isInitialized() const { return initialized_; }

private:
    // Build the search query URL.
    std::string buildSearchUrl(const std::string& query) const;

    // Extract readable text from HTML (strip tags, scripts, styles).
    std::string extractTextFromHtml(const std::string& html) const;

    // Extract the page title from HTML.
    std::string extractTitleFromHtml(const std::string& html) const;

    // Parse search results from the search engine's HTML response.
    std::vector<SearchResult> parseSearchResults(const std::string& html) const;

    HttpClient* httpClient_ = nullptr;
    vpn::VpnTunnel* vpnTunnel_ = nullptr;
    SearchConfig config_;
    bool initialized_ = false;
};

} // namespace llm
} // namespace lethe

#endif // LETHE_LLM_SEARCH_SERVICE_H

