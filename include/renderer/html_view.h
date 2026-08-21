#ifndef LETHE_RENDERER_HTML_VIEW_H
#define LETHE_RENDERER_HTML_VIEW_H

// html_view.h - Reader-mode HTML block model
//
// Lethe renders web content as clean structured text (no JavaScript, no
// CSS, no remote assets): the minimum feature set that cannot track or
// exploit the reader. This extractor turns HTML into an ordered list of
// typed text blocks that the viewport draws with Cairo.

#include <string>
#include <vector>

namespace lethe {

struct HtmlBlock {
    enum class Kind {
        Title,
        Heading1,
        Heading2,
        Heading3,
        Paragraph,
        ListItem,
    };

    Kind kind;
    std::string text;

    HtmlBlock(Kind k, const std::string& t) : kind(k), text(t) {}
};

class HtmlView {
public:
    HtmlView() = delete;

    // Document <title> text ("" when absent).
    static std::string extractTitle(const std::string& html);

    // Ordered readable blocks: headings, paragraphs, list items.
    // Scripts, styles, comments, and all markup are removed; entities are
    // decoded; whitespace is collapsed.
    static std::vector<HtmlBlock> extractBlocks(const std::string& html);

    // Decode the common named/numeric HTML entities.
    static std::string decodeEntities(const std::string& in);

    // Strip tags/scripts/styles/comments down to collapsed plain text.
    static std::string stripToText(const std::string& html);
};

} // namespace lethe

#endif // LETHE_RENDERER_HTML_VIEW_H
