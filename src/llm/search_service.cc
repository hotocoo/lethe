// search_service.cc — LLM search integration for Lethe
//
// Implements the search API used by the Aletheia OS LLM to perform web
// searches and read pages through the Lethe browser's network stack.

#include "llm/search_service.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace lethe {
namespace llm {

namespace {

// Decode the common named HTML entities into plain text.
std::string decodeEntities(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '&') { out += in[i]; continue; }
        if (in.compare(i, 4, "&lt;") == 0) { out += '<'; i += 3; }
        else if (in.compare(i, 4, "&gt;") == 0) { out += '>'; i += 3; }
        else if (in.compare(i, 5, "&amp;") == 0) { out += '&'; i += 4; }
        else if (in.compare(i, 6, "&quot;") == 0) { out += '"'; i += 5; }
        else if (in.compare(i, 6, "&apos;") == 0) { out += '\''; i += 5; }
        else if (in.compare(i, 6, "&nbsp;") == 0) { out += ' '; i += 5; }
        else out += in[i];
    }
    return out;
}

// Strip tags and collapse whitespace - used for anchor titles and snippets.
std::string stripTags(const std::string& html) {
    std::string text;
    text.reserve(html.size() / 2);
    bool inTag = false;
    for (char c : html) {
        if (c == '<') { inTag = true; continue; }
        if (c == '>') { inTag = false; continue; }
        if (!inTag) text += c;
    }
    std::string collapsed;
    collapsed.reserve(text.size());
    bool prevSpace = true;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!prevSpace) collapsed += ' ';
            prevSpace = true;
        } else {
            collapsed += c;
            prevSpace = false;
        }
    }
    // Trim trailing space left by the collapse loop.
    while (!collapsed.empty() && collapsed.back() == ' ') collapsed.pop_back();
    return collapsed;
}

} // namespace

SearchService::SearchService() = default;
SearchService::~SearchService() = default;

void SearchService::clearCaches() {
    pageIndex_.clear();
    pageLru_.clear();
    searchIndex_.clear();
    searchLru_.clear();
}

bool SearchService::pageCacheGet(const std::string& url, PageContent& out) {
    auto it = pageIndex_.find(url);
    if (it == pageIndex_.end()) return false;
    auto node = it->second;
    if (std::chrono::steady_clock::now() >= node->second.expires) {
        pageLru_.erase(node);
        pageIndex_.erase(it);
        return false;
    }
    out = node->second.content;
    out.fromCache = true;
    // Touch: move to front so the LRU bound keeps hot pages.
    pageLru_.splice(pageLru_.begin(), pageLru_, node);
    return true;
}

void SearchService::pageCachePut(const std::string& url, const PageContent& c) {
    if (!config_.cachePages || config_.maxCachedPages <= 0) return;
    auto it = pageIndex_.find(url);
    if (it != pageIndex_.end()) {
        it->second->second = PageCacheEntry{c,
            std::chrono::steady_clock::now() +
                std::chrono::seconds(config_.pageCacheTtlSec)};
        pageLru_.splice(pageLru_.begin(), pageLru_, it->second);
        return;
    }
    if (static_cast<int>(pageLru_.size()) >= config_.maxCachedPages) {
        pageIndex_.erase(pageLru_.back().first);
        pageLru_.pop_back();
    }
    pageLru_.emplace_front(url,
        PageCacheEntry{c, std::chrono::steady_clock::now() +
                              std::chrono::seconds(config_.pageCacheTtlSec)});
    pageIndex_[url] = pageLru_.begin();
}

bool SearchService::searchCacheGet(const std::string& key,
                                   std::vector<SearchResult>& out) {
    auto it = searchIndex_.find(key);
    if (it == searchIndex_.end()) return false;
    auto node = it->second;
    if (std::chrono::steady_clock::now() >= node->second.expires) {
        searchLru_.erase(node);
        searchIndex_.erase(it);
        return false;
    }
    out = node->second.results;
    searchLru_.splice(searchLru_.begin(), searchLru_, node);
    return true;
}

void SearchService::searchCachePut(
        const std::string& key, const std::vector<SearchResult>& results) {
    if (!config_.cacheSearches || config_.maxCachedSearches <= 0) return;
    auto it = searchIndex_.find(key);
    if (it != searchIndex_.end()) {
        it->second->second = SearchCacheEntry{results,
            std::chrono::steady_clock::now() +
                std::chrono::seconds(config_.searchCacheTtlSec)};
        searchLru_.splice(searchLru_.begin(), searchLru_, it->second);
        return;
    }
    if (static_cast<int>(searchLru_.size()) >= config_.maxCachedSearches) {
        searchIndex_.erase(searchLru_.back().first);
        searchLru_.pop_back();
    }
    searchLru_.emplace_front(key,
        SearchCacheEntry{results, std::chrono::steady_clock::now() +
                              std::chrono::seconds(config_.searchCacheTtlSec)});
    searchIndex_[key] = searchLru_.begin();
}

bool SearchService::initialize(HttpClient* httpClient, vpn::VpnTunnel* vpnTunnel,
                               const SearchConfig& config) {
    if (!httpClient) {
        std::cerr << "[lethe-llm] SearchService requires an HttpClient" << std::endl;
        return false;
    }

    httpClient_ = httpClient;
    vpnTunnel_ = vpnTunnel;
    config_ = config;
    initialized_ = true;

    std::cout << "[lethe-llm] Search service initialized (VPN: "
              << (config_.useVpn && vpnTunnel_ ? "on" : "off") << ")" << std::endl;
    return true;
}

bool SearchService::isUsingVpn() const {
    return config_.useVpn && vpnTunnel_ && vpnTunnel_->isConnected();
}

std::string SearchService::buildSearchUrl(const std::string& query) const {
    // URL-encode the query.
    std::string encoded;
    for (char c : query) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            encoded += c;
        } else {
            static const char hex[] = "0123456789ABCDEF";
            encoded += '%';
            encoded += hex[static_cast<unsigned char>(c) >> 4];
            encoded += hex[static_cast<unsigned char>(c) & 0xF];
        }
    }

    return config_.searchEngineUrl + "/search?q=" + encoded +
           "&num=" + std::to_string(config_.maxResults);
}

std::vector<SearchResult> SearchService::webSearch(const std::string& query) {
    std::vector<SearchResult> results;
    if (!initialized_) {
        std::cerr << "[lethe-llm] SearchService not initialized" << std::endl;
        return results;
    }

    const std::string url = buildSearchUrl(query);
    // Identical queries repeat constantly in agent workflows; the cache key
    // pins engine + query + limit so config changes never serve stale mixes.
    const std::string cacheKey = config_.searchEngineUrl + "|q=" + query +
                                 "|n=" + std::to_string(config_.maxResults) +
                                 "|" + config_.userAgent;
    if (searchCacheGet(cacheKey, results)) {
        std::cout << "[lethe-llm] Search (cached): " << query << " -> "
                  << results.size() << " results" << std::endl;
        return results;
    }

    std::cout << "[lethe-llm] Searching: " << query << std::endl;

    HttpRequest req;
    req.url = url;
    req.method = HttpMethod::GET;
    req.headers["User-Agent"] = config_.userAgent;
    req.headers["Accept"] = "text/html,application/xhtml+xml";

    HttpResponse resp = httpClient_->sendRequest(req);
    if (!resp.success) {
        std::cerr << "[lethe-llm] Search request failed: " << resp.error << std::endl;
        return results;
    }

    std::string html(resp.body.begin(), resp.body.end());
    results = parseSearchResults(html);
    if (!results.empty()) {
        searchCachePut(cacheKey, results);
    }

    std::cout << "[lethe-llm] Got " << results.size() << " results" << std::endl;
    return results;
}

PageContent SearchService::readPage(const std::string& url) {
    return fetchPage(url, /*allowCache=*/true);
}

PageContent SearchService::readPageFresh(const std::string& url) {
    return fetchPage(url, /*allowCache=*/false);
}

PageContent SearchService::fetchPage(const std::string& url, bool allowCache) {
    PageContent content;
    content.url = url;
    if (!initialized_) {
        content.error = "SearchService not initialized";
        std::cerr << "[lethe-llm] " << content.error << std::endl;
        return content;
    }

    std::cout << "[lethe-llm] Reading page: " << url << std::endl;

    // Fresh-cache hit for this exact URL: no network at all. LLM agents
    // re-read pages between reasoning steps far more than humans do.
    // Browser navigation (allowCache=false) always fetches for real.
    if (allowCache && pageCacheGet(url, content)) {
        std::cout << "[lethe-llm] Page (cached): " << content.title
                  << " (" << content.textContent.size() << " chars)" << std::endl;
        return content;
    }

    // Check if this should go through the VPN.
    content.viaVpn = isUsingVpn();

    HttpRequest req;
    req.url = url;
    req.method = HttpMethod::GET;
    req.headers["User-Agent"] = config_.userAgent;
    req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    req.headers["Accept-Language"] = "en-US,en;q=0.5";

    HttpResponse resp = httpClient_->sendRequest(req);
    if (!resp.success) {
        content.error = resp.error;
        std::cerr << "[lethe-llm] Page read failed: " << content.error << std::endl;
        return content;
    }

    content.statusCode = resp.statusCode;
    // The HTTP client followed redirects: report where the document really
    // came from so tabs, caches, and history record the final URL.
    if (!resp.finalUrl.empty()) content.url = resp.finalUrl;
    std::string html(resp.body.begin(), resp.body.end());
    content.title = extractTitleFromHtml(html);

    if (config_.extractReadableText) {
        content.textContent = extractTextFromHtml(html);
    } else {
        content.textContent = html;
    }

    content.success = true;
    // Cache under the REQUESTED url so repeat lookups hit without a
    // redirect chase; finalUrl stays inside the cached payload.
    pageCachePut(url, content);

    std::cout << "[lethe-llm] Read page: " << content.title
              << " (" << content.textContent.size() << " chars)" << std::endl;
    return content;
}

PageContent SearchService::searchAndRead(const std::string& query) {
    auto results = webSearch(query);
    if (results.empty()) {
        PageContent empty;
        empty.error = "No results found for query";
        return empty;
    }
    // Read the top result.
    return readPage(results[0].url);
}

std::string SearchService::extractTitleFromHtml(const std::string& html) const {
    size_t start = html.find("<title");
    if (start == std::string::npos) return "";
    start = html.find('>', start);
    if (start == std::string::npos) return "";
    start++;
    size_t end = html.find("</title>", start);
    if (end == std::string::npos) return "";
    return decodeEntities(html.substr(start, end - start));
}

std::string SearchService::extractTextFromHtml(const std::string& html) const {
    std::string text;
    text.reserve(html.size() / 2);

    bool inScript = false;
    bool inStyle = false;
    bool inTag = false;

    for (size_t i = 0; i < html.size(); i++) {
        char c = html[i];

        if (inTag) {
            if (c == '>') {
                inTag = false;
            }
            continue;
        }

        if (c == '<') {
            inTag = true;
            // Check for script/style tags.
            if (html.compare(i, 7, "<script") == 0) inScript = true;
            if (html.compare(i, 6, "<style") == 0) inStyle = true;
            continue;
        }

        if (inScript || inStyle) {
            if (html.compare(i, 9, "</script>") == 0) { inScript = false; i += 8; continue; }
            if (html.compare(i, 8, "</style>") == 0) { inStyle = false; i += 7; continue; }
            continue;
        }

        // Replace HTML entities (compare length must equal the literal's
        // full length - including the semicolon - or it never matches).
        if (c == '&') {
            if (html.compare(i, 4, "&lt;") == 0) { text += '<'; i += 3; continue; }
            if (html.compare(i, 4, "&gt;") == 0) { text += '>'; i += 3; continue; }
            if (html.compare(i, 5, "&amp;") == 0) { text += '&'; i += 4; continue; }
            if (html.compare(i, 6, "&quot;") == 0) { text += '"'; i += 5; continue; }
            if (html.compare(i, 6, "&nbsp;") == 0) { text += ' '; i += 5; continue; }
        }

        text += c;
    }

    // Collapse whitespace.
    std::string collapsed;
    collapsed.reserve(text.size());
    bool prevSpace = true;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!prevSpace) collapsed += ' ';
            prevSpace = true;
        } else {
            collapsed += c;
            prevSpace = false;
        }
    }

    return collapsed;
}

std::vector<SearchResult> SearchService::parseSearchResults(const std::string& html) const {
    std::vector<SearchResult> results;

    // Simple parser: look for result blocks. This is a basic implementation
    // that would be refined for specific search engines.
    // For the Aletheia built-in search, we expect a structured format.

    // Look for JSON-LD or structured data first.
    size_t jsonStart = html.find("<script type=\"application/ld+json\"");
    if (jsonStart != std::string::npos) {
        // Parse JSON-LD structured data (simplified).
        size_t jsonEnd = html.find("</script>", jsonStart);
        if (jsonEnd != std::string::npos) {
            std::string json = html.substr(jsonStart, jsonEnd - jsonStart);
            // In a full implementation, parse the JSON here.
            std::cout << "[lethe-llm] Found JSON-LD structured data" << std::endl;
        }
    }

    // Fallback: extract links and titles from result blocks.
    // This is a simplified heuristic parser.
    size_t pos = 0;
    int rank = 1;
    std::vector<std::string> seenUrls;
    while (rank <= config_.maxResults) {
        // Look for a result link pattern.
        size_t linkStart = html.find("<a ", pos);
        if (linkStart == std::string::npos) break;

        size_t hrefStart = html.find("href=\"", linkStart);
        if (hrefStart == std::string::npos) break;
        hrefStart += 6;
        size_t hrefEnd = html.find("\"", hrefStart);
        if (hrefEnd == std::string::npos) break;

        std::string url = html.substr(hrefStart, hrefEnd - hrefStart);

        // Only include http(s) URLs that aren't the search engine itself.
        if (url.rfind("http", 0) == 0 && url.find(config_.searchEngineUrl) == std::string::npos) {
            // Find the title (text between <a> and </a>).
            size_t textStart = html.find('>', hrefEnd);
            if (textStart != std::string::npos) {
                textStart++;
                size_t textEnd = html.find("</a>", textStart);
                if (textEnd != std::string::npos) {
                    // Titles arrive entity-encoded and may contain nested
                    // tags (e.g. <b>highlighted</b> terms): strip and decode
                    // so the LLM sees clean text.
                    std::string title =
                        decodeEntities(stripTags(html.substr(textStart, textEnd - textStart)));

                    // Navigation/footer anchors carry no visible text; they
                    // are noise, not results, and would poison the ranking.
                    if (!title.empty()) {
                        // Snippet: the readable text between this anchor's
                        // close and the next result link - typical search
                        // markup puts the summary right after the link.
                        std::string snippet;
                        const size_t afterAnchor = textEnd + 4;
                        const size_t nextLink = html.find("<a ", afterAnchor);
                        const size_t scanEnd = nextLink == std::string::npos
                            ? html.size()
                            : nextLink;
                        if (scanEnd > afterAnchor) {
                            snippet = decodeEntities(stripTags(
                                html.substr(afterAnchor, scanEnd - afterAnchor)));
                            // Keep snippets bounded: the LLM wants a hint,
                            // not a second copy of the page.
                            if (snippet.size() > 300) snippet.resize(300);
                        }

                        // Duplicate URLs (common with tracking-wrapped
                        // result blocks) would waste result slots.
                        const bool duplicate =
                            std::find(seenUrls.begin(), seenUrls.end(), url) != seenUrls.end();
                        if (!duplicate) {
                            seenUrls.push_back(url);
                            SearchResult result;
                            result.position = rank++;
                            result.url = url;
                            result.title = title;
                            result.snippet = snippet;
                            result.relevanceScore = 1.0 / static_cast<double>(result.position);
                            results.push_back(result);
                        }
                    }
                }
            }
        }

        pos = hrefEnd + 1;
    }

    return results;
}

} // namespace llm
} // namespace lethe

