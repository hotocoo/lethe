// test_page_templates.cc - Internal page HTML (block / error / reader)

#include "test_framework.h"
#include "renderer/page_templates.h"
#include "renderer/html_view.h"

using namespace lethe;

LETHE_TEST_CASE(PageTemplates_EscapesUntrustedText) {
    const std::string html = renderBlockPage(
        "https://evil.example/<script>", "reason <b>&</b>");
    CHECK(html.find("<script>") == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
    CHECK(html.find("reason &lt;b&gt;&amp;&lt;/b&gt;") != std::string::npos);
    CHECK(html.find("Blocked by Lethe") != std::string::npos);
}

LETHE_TEST_CASE(PageTemplates_ErrorPageNamesUrlAndMessage) {
    const std::string html = renderErrorPage("https://x.test/", "timed out");
    CHECK(html.find("https://x.test/") != std::string::npos);
    CHECK(html.find("timed out") != std::string::npos);
    CHECK(html.rfind("<!DOCTYPE html>", 0) == 0);
}

LETHE_TEST_CASE(PageTemplates_ReaderRendersBlocks) {
    std::vector<HtmlBlock> blocks = {
        {HtmlBlock::Kind::Title, "T <1>"},
        {HtmlBlock::Kind::Heading1, "H1"},
        {HtmlBlock::Kind::Paragraph, "para & more"},
        {HtmlBlock::Kind::ListItem, "one"},
        {HtmlBlock::Kind::ListItem, "two"},
        {HtmlBlock::Kind::Paragraph, "after"},
    };
    const std::string html = renderReaderPage("https://a.test/p", blocks);
    CHECK(html.find("<h1 class=\"title\">T &lt;1&gt;</h1>") != std::string::npos);
    CHECK(html.find("<h2>H1</h2>") != std::string::npos);
    CHECK(html.find("<p>para &amp; more</p>") != std::string::npos);
    // Consecutive list items share one <ul>.
    CHECK(html.find("<ul><li>one</li><li>two</li></ul>") != std::string::npos);
    CHECK(html.find("<script") == std::string::npos);
    CHECK(html.find("Content-Security-Policy") != std::string::npos);
}
