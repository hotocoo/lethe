// test_url_input.cc - Address-bar input normalization tests

#include "test_framework.h"
#include "browser/url_input.h"

using namespace lethe;

LETHE_TEST_CASE(UrlInput_ExplicitSchemesKept) {
    CHECK_EQ(normalizeAddressInput("https://example.com/a?b=1"),
             "https://example.com/a?b=1");
    CHECK_EQ(normalizeAddressInput("http://example.com"), "http://example.com");
    CHECK_EQ(normalizeAddressInput("HTTPS://Example.com"), "https://Example.com");
    CHECK_EQ(normalizeAddressInput("about:blank"), "about:blank");
    CHECK_EQ(normalizeAddressInput("  https://x.org  "), "https://x.org");
}

LETHE_TEST_CASE(UrlInput_BareHostsGetHttps) {
    CHECK_EQ(normalizeAddressInput("example.com"), "https://example.com");
    CHECK_EQ(normalizeAddressInput("www.example.com/path?q=1"),
             "https://www.example.com/path?q=1");
    CHECK_EQ(normalizeAddressInput("example.com:8443"), "https://example.com:8443");
    CHECK_EQ(normalizeAddressInput("sub.domain.co.uk"), "https://sub.domain.co.uk");
}

LETHE_TEST_CASE(UrlInput_LoopbackGetsHttp) {
    CHECK_EQ(normalizeAddressInput("localhost"), "http://localhost");
    CHECK_EQ(normalizeAddressInput("localhost:8080/x"), "http://localhost:8080/x");
    CHECK_EQ(normalizeAddressInput("127.0.0.1:3000"), "http://127.0.0.1:3000");
    CHECK_EQ(normalizeAddressInput("[::1]:8080"), "http://[::1]:8080");
    // Non-loopback IP literals stay https (the private-net guard decides).
    CHECK_EQ(normalizeAddressInput("192.168.1.1"), "https://192.168.1.1");
}

LETHE_TEST_CASE(UrlInput_SearchFallback) {
    CHECK_EQ(normalizeAddressInput("hello world"),
             "https://duckduckgo.com/?q=hello%20world");
    CHECK_EQ(normalizeAddressInput("what is lethe?"),
             "https://duckduckgo.com/?q=what%20is%20lethe%3F");
    CHECK_EQ(normalizeAddressInput("rust"), "https://duckduckgo.com/?q=rust");
    // Custom template.
    CHECK_EQ(normalizeAddressInput("a b", "https://s.example/?s={}"),
             "https://s.example/?s=a%20b");
}

LETHE_TEST_CASE(UrlInput_DangerousSchemesBecomeSearch) {
    // Fail closed: script/data/file/ftp schemes never navigate.
    CHECK_EQ(normalizeAddressInput("javascript:alert(1)"),
             "https://duckduckgo.com/?q=javascript%3Aalert%281%29");
    CHECK_EQ(normalizeAddressInput("file:///etc/passwd"),
             "https://duckduckgo.com/?q=file%3A%2F%2F%2Fetc%2Fpasswd");
    CHECK_EQ(normalizeAddressInput("data:text/html,hi"),
             "https://duckduckgo.com/?q=data%3Atext%2Fhtml%2Chi");
}

LETHE_TEST_CASE(UrlInput_Empty) {
    CHECK_EQ(normalizeAddressInput(""), "");
    CHECK_EQ(normalizeAddressInput("   "), "");
}

LETHE_TEST_CASE(UrlInput_PercentEncode) {
    CHECK_EQ(percentEncodeQueryComponent("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    CHECK_EQ(percentEncodeQueryComponent("safe-_.~AZaz09"), "safe-_.~AZaz09");
}
