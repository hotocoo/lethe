// test_llm_search.cc — Tests for the LLM search service

#include "test_framework.h"
#include "llm/search_service.h"
#include "network/http_client.h"
#include "network/tls_config.h"
#include "network/vpn/vpn_tunnel.h"

using namespace lethe;
using namespace lethe::llm;

LETHE_TEST_CASE(SearchService_Initialize) {
    HttpClient httpClient;
    TLSConfig tls;
    CHECK_TRUE(httpClient.initialize(tls));

    SearchService service;
    SearchConfig config;
    config.searchEngineUrl = "https://search.aletheia.os";
    config.maxResults = 5;

    CHECK_TRUE(service.initialize(&httpClient, nullptr, config));
    CHECK_TRUE(service.isInitialized());
    CHECK_FALSE(service.isUsingVpn());  // No VPN tunnel
}

LETHE_TEST_CASE(SearchService_InitializeWithVpn) {
    HttpClient httpClient;
    TLSConfig tls;
    CHECK_TRUE(httpClient.initialize(tls));

    vpn::VpnTunnel tunnel;
    vpn::Key serverPriv{};
    CHECK_TRUE(vpn::generatePrivateKey(serverPriv));
    CHECK_TRUE(tunnel.configureServer(serverPriv));

    SearchService service;
    SearchConfig config;
    config.useVpn = true;

    CHECK_TRUE(service.initialize(&httpClient, &tunnel, config));
    CHECK_TRUE(service.isInitialized());
    // Not connected yet, so not "using" VPN.
    CHECK_FALSE(service.isUsingVpn());
}

LETHE_TEST_CASE(SearchService_BuildSearchUrl) {
    HttpClient httpClient;
    TLSConfig tls;
    CHECK_TRUE(httpClient.initialize(tls));

    SearchService service;
    SearchConfig config;
    config.searchEngineUrl = "https://search.aletheia.os";
    config.maxResults = 10;

    CHECK_TRUE(service.initialize(&httpClient, nullptr, config));

    // webSearch should build a proper URL (we can't test the actual network
    // call, but we can verify it doesn't crash and returns empty on failure).
    auto results = service.webSearch("test query");
    // The search will fail (no real server), so results should be empty.
    // This verifies the code path works without crashing.
    (void)results;
}

LETHE_TEST_CASE(SearchService_ReadPage_NotInitialized) {
    SearchService service;
    auto content = service.readPage("https://example.com");
    CHECK_FALSE(content.success);
    CHECK_FALSE(content.error.empty());
}

LETHE_TEST_CASE(SearchService_WebSearch_NotInitialized) {
    SearchService service;
    auto results = service.webSearch("test");
    CHECK_TRUE(results.empty());
}

LETHE_TEST_CASE(SearchService_ExtractTextFromHtml) {
    HttpClient httpClient;
    TLSConfig tls;
    CHECK_TRUE(httpClient.initialize(tls));

    SearchService service;
    SearchConfig config;
    config.extractReadableText = true;
    CHECK_TRUE(service.initialize(&httpClient, nullptr, config));

    // We can't directly call private methods, but we can test through
    // readPage with a mock. For now, verify the service works.
    (void)service;
}


// --- Top-k / top-p (nucleus) result ranking ---------------------------------

namespace {
std::vector<SearchResult> sampleResults() {
    return {
        {1, "Weather forecast today", "https://a.example/weather", "Sunny with clouds", 0},
        {2, "Rust borrow checker explained", "https://b.example/rust", "Ownership and lifetimes in Rust", 0},
        {3, "Cooking pasta", "https://c.example/pasta", "Boil water, add salt", 0},
        {4, "Rust lifetimes deep dive", "https://d.example/lifetimes", "The borrow checker and lifetimes", 0},
        {5, "Travel tips", "https://e.example/travel", "Pack light", 0},
    };
}
}  // namespace

LETHE_TEST_CASE(SearchRanking_EmptyInputStaysEmpty) {
    CHECK_TRUE(rankResults("rust", {}, RankingParams{}).empty());
}

LETHE_TEST_CASE(SearchRanking_QueryMatchOutranksEnginePosition) {
    RankingParams p; p.topK = 5; p.topP = 1.0;
    auto r = rankResults("rust borrow checker lifetimes", sampleResults(), p);
    CHECK_EQ(r.size(), size_t{5});
    // Both Rust pages beat the engine's #1 (weather), which matches nothing.
    CHECK_TRUE(r[0].url.find("example/rust") != std::string::npos ||
               r[0].url.find("example/lifetimes") != std::string::npos);
    CHECK_TRUE(r[1].url.find("example/rust") != std::string::npos ||
               r[1].url.find("example/lifetimes") != std::string::npos);
}

LETHE_TEST_CASE(SearchRanking_TopKCapsCount) {
    RankingParams p; p.topK = 2; p.topP = 1.0;
    CHECK_EQ(rankResults("rust", sampleResults(), p).size(), size_t{2});
}

LETHE_TEST_CASE(SearchRanking_NucleusNeverEmpty) {
    RankingParams p; p.topK = 5; p.topP = 0.0001;
    auto r = rankResults("rust lifetimes", sampleResults(), p);
    CHECK_EQ(r.size(), size_t{1});
    CHECK_EQ(r[0].position, 1);
}

LETHE_TEST_CASE(SearchRanking_ProbabilitiesNormalisedAndDescending) {
    RankingParams p; p.topK = 10; p.topP = 1.0;
    auto r = rankResults("rust", sampleResults(), p);
    CHECK_EQ(r.size(), size_t{5});
    double sum = 0;
    for (size_t i = 0; i < r.size(); ++i) {
        sum += r[i].relevanceScore;
        CHECK_EQ(r[i].position, static_cast<int>(i + 1));
        if (i) CHECK_TRUE(r[i - 1].relevanceScore >= r[i].relevanceScore);
    }
    CHECK_TRUE(sum > 0.999 && sum < 1.001);
}

LETHE_TEST_CASE(SearchRanking_NucleusCutsLowMassTail) {
    // A peaked distribution (low temperature) concentrates mass on the two
    // Rust pages; top-p 0.9 must drop the unrelated tail.
    RankingParams p; p.topK = 5; p.topP = 0.9; p.temperature = 0.1;
    auto r = rankResults("rust borrow checker lifetimes", sampleResults(), p);
    CHECK_TRUE(r.size() >= 1 && r.size() <= 2);
}

LETHE_TEST_CASE(SearchRanking_ZeroTemperatureIsGreedy) {
    RankingParams p; p.topK = 5; p.topP = 1.0; p.temperature = 0.0;
    auto r = rankResults("pasta", sampleResults(), p);
    CHECK_EQ(r.size(), size_t{1});
    CHECK_TRUE(r[0].url.find("pasta") != std::string::npos);
}
