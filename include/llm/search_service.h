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
#include <list>
#include <unordered_map>
#include <chrono>
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
    bool fromCache = false;  // Served from the service's TTL/LRU cache
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

    // Caching: LLM agents re-read the same pages and repeat queries far
    // more than humans do, so successful reads are memoized briefly.
    bool cachePages = true;          // Memoize successful page reads
    int maxCachedPages = 32;         // LRU bound for the page cache
    int pageCacheTtlSec = 600;       // Freshness window for cached pages
    bool cacheSearches = true;       // Memoize identical query results
    int maxCachedSearches = 16;      // LRU bound for the search cache
    int searchCacheTtlSec = 300;     // Freshness window for cached results
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

    // Read a page and return its readable content for the LLM. Successful
    // reads are memoized briefly (TTL+LRU): agent workflows re-read pages
    // far more often than humans do.
    PageContent readPage(const std::string& url);

    // Read a page with the cache bypassed - always a real network fetch
    // through the secure stack. Browser navigation uses this so every
    // document load stays a genuine, policy-checked page load.
    PageContent readPageFresh(const std::string& url);

    // Perform a search and read the top result (convenience for the LLM).
    PageContent searchAndRead(const std::string& query);

    // Whether the search service is using the VPN.
    bool isUsingVpn() const;

    // Whether the search service is properly initialized.
    bool isInitialized() const { return initialized_; }

    // Drop every memoized page and search result (e.g. after a privacy-
    // sensitive state change). Cache bounds/TTLs come from SearchConfig.
    void clearCaches();

    // Current cache occupancy (for introspection and tests).
    size_t pageCacheSize() const { return pageLru_.size(); }
    size_t searchCacheSize() const { return searchLru_.size(); }

private:
    // Build the search query URL.
    std::string buildSearchUrl(const std::string& query) const;

    // Extract readable text from HTML (strip tags, scripts, styles).
    std::string extractTextFromHtml(const std::string& html) const;

    // Extract the page title from HTML.
    std::string extractTitleFromHtml(const std::string& html) const;

protected:
    // Parse search results from the search engine's HTML response.
    // Protected: test subclasses exercise it directly.
    std::vector<SearchResult> parseSearchResults(const std::string& html) const;

private:

    // --- TTL+LRU caches (successful fetches only) ---
    struct PageCacheEntry {
        PageContent content;
        std::chrono::steady_clock::time_point expires{};
    };
    struct SearchCacheEntry {
        std::vector<SearchResult> results;
        std::chrono::steady_clock::time_point expires{};
    };
    // list order == recency order (front = most recent).
    std::list<std::pair<std::string, PageCacheEntry>> pageLru_;
    std::unordered_map<std::string,
        std::list<std::pair<std::string, PageCacheEntry>>::iterator> pageIndex_;
    std::list<std::pair<std::string, SearchCacheEntry>> searchLru_;
    std::unordered_map<std::string,
        std::list<std::pair<std::string, SearchCacheEntry>>::iterator> searchIndex_;

    bool pageCacheGet(const std::string& url, PageContent& out);
    void pageCachePut(const std::string& url, const PageContent& c);
    bool searchCacheGet(const std::string& key, std::vector<SearchResult>& out);
    void searchCachePut(const std::string& key,
                        const std::vector<SearchResult>& results);

    // Shared implementation behind readPage/readPageFresh.
    PageContent fetchPage(const std::string& url, bool allowCache);

    HttpClient* httpClient_ = nullptr;
    vpn::VpnTunnel* vpnTunnel_ = nullptr;
    SearchConfig config_;
    bool initialized_ = false;
};

} // namespace llm
} // namespace lethe

#endif // LETHE_LLM_SEARCH_SERVICE_H

