// test_site_reputation.cc - local URL risk assessment

#include "test_framework.h"

#include "security/site_reputation.h"

using namespace lethe;

namespace {

bool hasFinding(const ThreatReport& report, const std::string& id) {
    for (const ThreatFinding& finding : report.findings)
        if (finding.id == id) return true;
    return false;
}

}  // namespace

LETHE_TEST_CASE(SiteReputation_LeavesOrdinarySitesAlone) {
    for (const char* url : {"https://example.com/", "https://en.wikipedia.org/wiki/Browser",
                            "https://github.com/acotech/lethe",
                            "https://www.apple.com/mac/"}) {
        const ThreatReport report = assessUrl(url);
        CHECK_FALSE(report.blocked());
        CHECK(report.clean());
    }
}

LETHE_TEST_CASE(SiteReputation_FlagsBrandInSubdomain) {
    const ThreatReport report = assessUrl("https://apple.com.secure-login.ru/verify");
    CHECK(hasFinding(report, "url.brand_impersonation"));
    CHECK(report.blocked());
}

LETHE_TEST_CASE(SiteReputation_FlagsTyposquat) {
    const ThreatReport report = assessUrl("https://paypa1.com/account/login");
    CHECK(hasFinding(report, "url.brand_impersonation"));
}

LETHE_TEST_CASE(SiteReputation_FlagsUserInfoAuthority) {
    const ThreatReport report = assessUrl("https://www.apple.com@evil.example/path");
    CHECK(hasFinding(report, "url.userinfo"));
    CHECK(report.blocked());
}

LETHE_TEST_CASE(SiteReputation_FlagsPunycodeAndIpLiterals) {
    CHECK(hasFinding(assessUrl("https://xn--pple-43d.com/"), "url.punycode"));
    CHECK(hasFinding(assessUrl("https://93.184.216.34/login"), "url.ip_literal"));
}

LETHE_TEST_CASE(SiteReputation_FlagsOpaqueTopLevelNavigation) {
    CHECK(assessUrl("data:text/html;base64,PHNjcmlwdD4=").blocked());
    CHECK(assessUrl("javascript:alert(1)").blocked());
}

LETHE_TEST_CASE(SiteReputation_FlagsDirectExecutableLinks) {
    const ThreatReport report =
        assessUrl("https://files.example.com/downloads/setup.dmg");
    CHECK(hasFinding(report, "url.executable_link"));
}

LETHE_TEST_CASE(SiteReputation_FlagsPlaintextNavigation) {
    CHECK(hasFinding(assessUrl("http://example.com/"), "url.plaintext"));
}

LETHE_TEST_CASE(SiteReputation_RespectsUserAllowList) {
    SiteReputationOptions options;
    options.allowedHosts = {"93.184.216.34"};
    CHECK(assessUrl("https://93.184.216.34/login", options).clean());
}

LETHE_TEST_CASE(SiteReputation_EditDistanceIsBounded) {
    CHECK_EQ(editDistance("apple.com", "apple.com", 2), size_t(0));
    CHECK_EQ(editDistance("apple.com", "appie.com", 2), size_t(1));
    CHECK(editDistance("apple.com", "completely-different.example", 2) > size_t(2));
}

LETHE_TEST_CASE(SiteReputation_DeepSubdomainsAreSuspicious) {
    const ThreatReport report =
        assessUrl("https://a.b.c.d.e.example.com/");
    CHECK(hasFinding(report, "url.deep_subdomains"));
}
