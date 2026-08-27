// test_html_view.cc - Reader-mode HTML extraction tests

#include "test_framework.h"
#include "renderer/html_view.h"

#include <string>
#include <vector>

using namespace lethe;

LETHE_TEST_CASE(HtmlView_TitleExtraction) {
    CHECK_EQ(HtmlView::extractTitle(
        "<html><head><title>My Page</title></head></html>"), "My Page");
    CHECK_EQ(HtmlView::extractTitle(
        "<TITLE>Upper</TITLE>"), "Upper");
    CHECK_EQ(HtmlView::extractTitle("<html><body>no title</body></html>"), "");
    // Scripts must not leak into the title.
    CHECK_EQ(HtmlView::extractTitle(
        "<title>T</title><script>document.write('<title>evil</title>')</script>"),
        "T");
}

LETHE_TEST_CASE(HtmlView_EntityDecoding) {
    CHECK_EQ(HtmlView::decodeEntities("a &amp; b"), "a & b");
    CHECK_EQ(HtmlView::decodeEntities("&lt;tag&gt;"), "<tag>");
    CHECK_EQ(HtmlView::decodeEntities("&quot;q&quot; &apos;a&apos;"), "\"q\" 'a'");
    CHECK_EQ(HtmlView::decodeEntities("a&nbsp;b"), "a b");
    CHECK_EQ(HtmlView::decodeEntities("&#65;&#x42;"), "AB");
    // Non-ASCII numeric references become UTF-8, never raw Latin-1 bytes.
    CHECK_EQ(HtmlView::decodeEntities("&#233;"), "\xC3\xA9");        // e-acute
    CHECK_EQ(HtmlView::decodeEntities("&#x2014;"), "\xE2\x80\x94");  // em dash
    CHECK_EQ(HtmlView::decodeEntities("&#128512;"), "\xF0\x9F\x98\x80"); // emoji
    CHECK_EQ(HtmlView::decodeEntities("&#xD800;&#1;"), "");           // invalid dropped
    // Unknown and malformed entities stay readable.
    CHECK_EQ(HtmlView::decodeEntities("&unknown; x"), "&unknown; x");
    CHECK_EQ(HtmlView::decodeEntities("100 & 200"), "100 & 200");
}

LETHE_TEST_CASE(HtmlView_ScriptAndStyleStripped) {
    const std::string html =
        "<html><head><style>body{color:red}</style>"
        "<script>alert('pwned')</script></head>"
        "<body><p>visible text</p></body></html>";
    const std::string text = HtmlView::stripToText(html);
    CHECK_TRUE(text.find("alert") == std::string::npos);
    CHECK_TRUE(text.find("color:red") == std::string::npos);
    CHECK_TRUE(text.find("visible text") != std::string::npos);
}

LETHE_TEST_CASE(HtmlView_Blocks_TypesAndOrder) {
    const std::string html =
        "<html><head><title>Doc</title></head><body>"
        "<h1>Big Heading</h1>"
        "<p>First paragraph.</p>"
        "<h2>Sub Heading</h2>"
        "<ul><li>item one</li><li>item two</li></ul>"
        "<h3>Small Heading</h3>"
        "<p>Last paragraph with <b>bold</b> inline markup.</p>"
        "</body></html>";

    auto blocks = HtmlView::extractBlocks(html);
    CHECK_EQ(blocks.size(), 8u);

    CHECK(blocks[0].kind == HtmlBlock::Kind::Title);
    CHECK_EQ(blocks[0].text, "Doc");

    CHECK(blocks[1].kind == HtmlBlock::Kind::Heading1);
    CHECK_EQ(blocks[1].text, "Big Heading");

    CHECK(blocks[2].kind == HtmlBlock::Kind::Paragraph);
    CHECK_EQ(blocks[2].text, "First paragraph.");

    CHECK(blocks[3].kind == HtmlBlock::Kind::Heading2);
    CHECK_EQ(blocks[3].text, "Sub Heading");

    CHECK(blocks[4].kind == HtmlBlock::Kind::ListItem);
    CHECK_EQ(blocks[4].text, "item one");
    CHECK(blocks[5].kind == HtmlBlock::Kind::ListItem);
    CHECK_EQ(blocks[5].text, "item two");

    CHECK(blocks[6].kind == HtmlBlock::Kind::Heading3);
    CHECK_EQ(blocks[6].text, "Small Heading");

    CHECK(blocks[7].kind == HtmlBlock::Kind::Paragraph);
    CHECK_EQ(blocks[7].text, "Last paragraph with bold inline markup.");
}

LETHE_TEST_CASE(HtmlView_EntitiesDecodedInBlocks) {
    auto blocks = HtmlView::extractBlocks(
        "<p>Fish &amp; Chips &lt;3</p>");
    CHECK_EQ(blocks.size(), 1u);
    CHECK_EQ(blocks[0].text, "Fish & Chips <3");
}

LETHE_TEST_CASE(HtmlView_CommentsAndEmptyBlocksDropped) {
    auto blocks = HtmlView::extractBlocks(
        "<p>keep</p><!-- <p>hidden comment</p> --><p>   </p><p>also keep</p>");
    CHECK_EQ(blocks.size(), 2u);
    CHECK_EQ(blocks[0].text, "keep");
    CHECK_EQ(blocks[1].text, "also keep");
}

LETHE_TEST_CASE(HtmlView_BoilerplateRegionsDropped) {
    const std::string html =
        "<html><body><nav><a>Home</a><a>Menu</a></nav>"
        "<header><span>Site banner</span></header>"
        "<h1>Article</h1><p>Body text.</p>"
        "<aside>Related links</aside><footer>Copyright</footer></body></html>";
    const auto blocks = HtmlView::extractBlocks(html);
    std::string joined;
    for (const auto& b : blocks) joined += b.text + "|";
    CHECK(joined.find("Article") != std::string::npos);
    CHECK(joined.find("Body text.") != std::string::npos);
    CHECK(joined.find("Home") == std::string::npos);
    CHECK(joined.find("Site banner") == std::string::npos);
    CHECK(joined.find("Related links") == std::string::npos);
    CHECK(joined.find("Copyright") == std::string::npos);
}
