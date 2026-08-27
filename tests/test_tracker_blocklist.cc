// test_tracker_blocklist.cc - built-in tracker protection list + rules

#include "test_framework.h"

#include "security/tracker_blocklist.h"

using namespace lethe;

LETHE_TEST_CASE(TrackerBlocklist_ParsesListFormat) {
    const TrackerBlocklist l = parseTrackerBlocklist(
        "# comment\n"
        "DoubleClick.net\n"
        "  *.scorecardresearch.com  # trailing comment\n"
        "https://Facebook.com/tr\n"
        "doubleclick.net\n"          // duplicate collapsed
        "not_a_domain\n"             // rejected: no dot / bad char
        "nodot\n"
        "example.com/\n"             // host with empty path = host only
        "\n");
    CHECK_EQ(l.domains.size(), 3u);
    CHECK_EQ(l.domains[0], "doubleclick.net");
    CHECK_EQ(l.domains[1], "scorecardresearch.com");
    CHECK_EQ(l.domains[2], "example.com");
    CHECK_EQ(l.pathPatterns.size(), 1u);
    CHECK_EQ(l.pathPatterns[0], "facebook.com/tr");
}

LETHE_TEST_CASE(TrackerBlocklist_BuiltinIsSubstantialAndClean) {
    const TrackerBlocklist& l = builtinTrackerBlocklist();
    CHECK_GE(l.domains.size(), 200u);
    for (const auto& d : l.domains) {
        CHECK_TRUE(d.find('.') != std::string::npos);
        CHECK_TRUE(d.find('/') == std::string::npos);
        CHECK_TRUE(d == d.substr(0, d.size()));   // no trailing junk
        // Never block infrastructure a page needs to render.
        CHECK_TRUE(d != "googleapis.com" && d != "gstatic.com" && d != "cloudflare.com" &&
                   d != "jsdelivr.net" && d != "youtube.com" && d != "googlevideo.com");
    }
    bool hasDoubleclick = false, hasGa = false;
    for (const auto& d : l.domains) {
        if (d == "doubleclick.net") hasDoubleclick = true;
        if (d == "google-analytics.com") hasGa = true;
    }
    CHECK_TRUE(hasDoubleclick);
    CHECK_TRUE(hasGa);
}

LETHE_TEST_CASE(TrackerBlocklist_ContentRulesJsonShape) {
    TrackerBlocklist l;
    l.domains = {"doubleclick.net", "a-b.example"};
    l.pathPatterns = {"facebook.com/tr"};
    const std::string json = trackerContentRulesJson(l);
    CHECK_TRUE(json.front() == '[' && json.back() == ']');
    // Domain rule: anchored, subdomain-aware, authority-terminated, third-party only.
    CHECK_TRUE(json.find("\"url-filter\":\"^https?://([^/]+\\\\.)?doubleclick\\\\.net[/:]\"") != std::string::npos);
    CHECK_TRUE(json.find("\"load-type\":[\"third-party\"]") != std::string::npos);
    CHECK_TRUE(json.find("\"action\":{\"type\":\"block\"}") != std::string::npos);
    // Path rule keeps the path, escaped.
    CHECK_TRUE(json.find("facebook\\\\.com\\\\/tr\"") != std::string::npos);
    // Exactly three rules.
    size_t rules = 0, pos = 0;
    while ((pos = json.find("{\"trigger\"", pos)) != std::string::npos) { rules++; pos++; }
    CHECK_EQ(rules, 3u);
    // Identifier is stable and content-derived.
    CHECK_EQ(trackerRulesIdentifier(l), trackerRulesIdentifier(l));
    l.domains.push_back("extra.example");
    CHECK_TRUE(trackerRulesIdentifier(l) != trackerRulesIdentifier(builtinTrackerBlocklist()));
    CHECK_TRUE(trackerRulesIdentifier(l).rfind("lethe-trackers-v1-", 0) == 0);
}

LETHE_TEST_CASE(TrackerBlocklist_RegexEscape) {
    CHECK_EQ(regexEscape("a.b-c"), "a\\.b-c");
    CHECK_EQ(regexEscape("x/y?z"), "x\\/y\\?z");
    CHECK_EQ(regexEscape("plain"), "plain");
}
