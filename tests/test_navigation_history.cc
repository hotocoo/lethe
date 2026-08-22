// test_navigation_history.cc — Back/forward session history semantics

#include "test_framework.h"
#include "browser/navigation_history.h"

using namespace lethe;

LETHE_TEST_CASE(NavHistory_AppendAndCursor) {
    NavigationHistory h;
    CHECK_TRUE(h.empty());
    CHECK_TRUE(h.current() == nullptr);

    h.addEntry("http://a/", "A");
    h.addEntry("http://b/", "B");
    CHECK_EQ(h.size(), 2u);
    CHECK_TRUE(h.canGoBack());     // cursor on b: a is behind it
    CHECK_FALSE(h.canGoForward()); // nothing ahead of b
    CHECK_TRUE(h.current() != nullptr);
    CHECK_EQ(h.current()->url, std::string("http://b/"));
}

LETHE_TEST_CASE(NavHistory_BackForwardEdges) {
    NavigationHistory h;
    CHECK_TRUE(h.goBack() == nullptr);
    CHECK_TRUE(h.goForward() == nullptr);

    h.addEntry("http://a/");
    h.addEntry("http://b/");
    h.addEntry("http://c/");
    CHECK_TRUE(h.peekBack() != nullptr);
    CHECK_EQ(h.peekBack()->url, std::string("http://b/"));

    const auto* e = h.goBack();
    CHECK_TRUE(e != nullptr);
    CHECK_EQ(e->url, std::string("http://b/"));
    CHECK_TRUE(h.canGoBack());
    CHECK_TRUE(h.canGoForward());

    e = h.goBack();
    CHECK_EQ(e->url, std::string("http://a/"));
    CHECK_FALSE(h.canGoBack());
    CHECK_TRUE(h.goBack() == nullptr);
    CHECK_TRUE(h.peekBack() == nullptr);

    e = h.goForward();
    CHECK_EQ(e->url, std::string("http://b/"));
}

LETHE_TEST_CASE(NavHistory_NewEntryTruncatesForwardBranch) {
    NavigationHistory h;
    h.addEntry("http://a/");
    h.addEntry("http://b/");
    h.addEntry("http://c/");
    h.goBack(); // at b, forward holds c
    h.goBack(); // at a, forward holds b,c
    CHECK_TRUE(h.canGoForward());

    // A fresh navigation from the past drops b and c from the future.
    h.addEntry("http://d/");
    CHECK_FALSE(h.canGoForward());
    CHECK_EQ(h.size(), 2u);
    CHECK_EQ(h.entries()[0].url, std::string("http://a/"));
    CHECK_EQ(h.entries()[1].url, std::string("http://d/"));
    CHECK_TRUE(h.containsUrl("http://d/"));
    CHECK_FALSE(h.containsUrl("http://b/"));
}

LETHE_TEST_CASE(NavHistory_CapKeepsMostRecent) {
    NavigationHistory h;
    for (int i = 0; i < 1200; i++) {
        h.addEntry("http://page" + std::to_string(i) + "/");
    }
    CHECK_EQ(h.size(), 1000u);
    CHECK_EQ(h.entries().front().url, std::string("http://page200/"));
    CHECK_EQ(h.entries().back().url, std::string("http://page1199/"));
    CHECK_FALSE(h.containsUrl("http://page199/"));
    CHECK_TRUE(h.current() != nullptr);
    CHECK_EQ(h.current()->url, std::string("http://page1199/"));
}

LETHE_TEST_CASE(NavHistory_ClearResetsCursor) {
    NavigationHistory h;
    h.addEntry("http://a/");
    h.addEntry("http://b/");
    h.goBack();
    h.clear();
    CHECK_TRUE(h.empty());
    CHECK_FALSE(h.canGoBack());
    CHECK_FALSE(h.canGoForward());
    h.addEntry("http://x/");
    CHECK_TRUE(h.current() != nullptr);
    CHECK_EQ(h.current()->url, std::string("http://x/"));
}
