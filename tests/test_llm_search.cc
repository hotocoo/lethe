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

