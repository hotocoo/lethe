// html_view.cc - Reader-mode HTML extraction

#include "renderer/html_view.h"

#include <cctype>

namespace lethe {

namespace {

std::string toLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Remove every  <tag ...> ... </tag>  region (case-insensitive).
void removeRegions(std::string& html, const std::string& tag) {
    const std::string openLower = "<" + tag;
    size_t pos = 0;
    while (true) {
        // Scan case-insensitively.
        size_t start = std::string::npos;
        for (size_t i = pos; i + openLower.size() <= html.size(); i++) {
            bool match = true;
            for (size_t j = 0; j < openLower.size(); j++) {
                if (std::tolower(static_cast<unsigned char>(html[i + j])) !=
                    openLower[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                // Must be the full tag name (next char not a letter).
                const char next = html[i + openLower.size()];
                if (!std::isalnum(static_cast<unsigned char>(next))) {
                    start = i;
                    break;
                }
            }
        }
        if (start == std::string::npos) return;

        size_t end = std::string::npos;
        const std::string closeTag = "</" + tag;
        for (size_t i = start; i + closeTag.size() <= html.size(); i++) {
            bool match = true;
            for (size_t j = 0; j < closeTag.size(); j++) {
                if (std::tolower(static_cast<unsigned char>(html[i + j])) !=
                    closeTag[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                end = html.find('>', i + closeTag.size());
                if (end != std::string::npos) end += 1;
                break;
            }
        }
        if (end == std::string::npos) {
            html.erase(start); // unterminated: drop the rest
            return;
        }
        html.erase(start, end - start);
        pos = start;
    }
}

// Block-level tag name -> block kind (empty name = not a boundary).
bool blockBoundary(const std::string& tagLower, HtmlBlock::Kind& kind,
                   bool& isTitle) {
    isTitle = false;
    if (tagLower == "h1") { kind = HtmlBlock::Kind::Heading1; return true; }
    if (tagLower == "h2") { kind = HtmlBlock::Kind::Heading2; return true; }
    if (tagLower == "h3" || tagLower == "h4" || tagLower == "h5" ||
        tagLower == "h6") {
        kind = HtmlBlock::Kind::Heading3;
        return true;
    }
    if (tagLower == "p" || tagLower == "div" || tagLower == "br" ||
        tagLower == "section" || tagLower == "article" || tagLower == "blockquote") {
        kind = HtmlBlock::Kind::Paragraph;
        return true;
    }
    if (tagLower == "li") { kind = HtmlBlock::Kind::ListItem; return true; }
    if (tagLower == "title") { kind = HtmlBlock::Kind::Title; isTitle = true; return true; }
    return false;
}

} // namespace

std::string HtmlView::decodeEntities(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        if (in[i] != '&') {
            out.push_back(in[i++]);
            continue;
        }
        const size_t semi = in.find(';', i);
        if (semi == std::string::npos || semi - i > 10) {
            out.push_back(in[i++]);
            continue;
        }
        const std::string ent = in.substr(i + 1, semi - i - 1);
        if (ent == "amp") out.push_back('&');
        else if (ent == "lt") out.push_back('<');
        else if (ent == "gt") out.push_back('>');
        else if (ent == "quot") out.push_back('"');
        else if (ent == "apos") out.push_back('\'');
        else if (ent == "nbsp") out.push_back(' ');
        else if (!ent.empty() && ent[0] == '#') {
            // Numeric character reference (decimal or hex).
            long code = -1;
            try {
                if (ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X')) {
                    code = std::stol(ent.substr(2), nullptr, 16);
                } else {
                    code = std::stol(ent.substr(1), nullptr, 10);
                }
            } catch (...) {
                code = -1;
            }
            // Latin-1 range maps directly; anything else becomes '?'.
            if (code >= 32 && code <= 255) out.push_back(static_cast<char>(code));
            else if (code > 255) out.push_back('?');
        } else {
            out += "&" + ent + ";"; // unknown entity: keep literally
        }
        i = semi + 1;
    }
    return out;
}

std::string HtmlView::stripToText(const std::string& html) {
    std::string doc = html;
    // Comments first so they cannot hide tag boundaries.
    size_t c = 0;
    while ((c = doc.find("<!--", c)) != std::string::npos) {
        const size_t end = doc.find("-->", c);
        if (end == std::string::npos) { doc.erase(c); break; }
        doc.erase(c, end + 3 - c);
    }
    removeRegions(doc, "script");
    removeRegions(doc, "style");

    std::string text;
    text.reserve(doc.size());
    bool inTag = false;
    for (char ch : doc) {
        if (ch == '<') { inTag = true; text.push_back(' '); continue; }
        if (inTag) {
            if (ch == '>') inTag = false;
            continue;
        }
        text.push_back(ch);
    }

    // Collapse whitespace.
    std::string collapsed;
    collapsed.reserve(text.size());
    bool prevSpace = true;
    for (char ch : text) {
        if (std::isspace(static_cast<unsigned char>(ch))) {
            if (!prevSpace) collapsed.push_back(' ');
            prevSpace = true;
        } else {
            collapsed.push_back(ch);
            prevSpace = false;
        }
    }
    return collapsed;
}

std::string HtmlView::extractTitle(const std::string& html) {
    std::string doc = html;
    removeRegions(doc, "script");
    // Case-insensitive scan for the opening tag.
    size_t start = std::string::npos;
    for (size_t i = 0; i + 6 <= doc.size(); i++) {
        if ((doc[i] == '<') &&
            std::tolower(static_cast<unsigned char>(doc[i + 1])) == 't' &&
            std::tolower(static_cast<unsigned char>(doc[i + 2])) == 'i' &&
            std::tolower(static_cast<unsigned char>(doc[i + 3])) == 't' &&
            std::tolower(static_cast<unsigned char>(doc[i + 4])) == 'l' &&
            std::tolower(static_cast<unsigned char>(doc[i + 5])) == 'e') {
            start = i;
            break;
        }
    }
    if (start == std::string::npos) return "";
    start = doc.find('>', start);
    if (start == std::string::npos) return "";
    // Case-insensitive scan for the closing tag.
    size_t end = std::string::npos;
    for (size_t i = start; i + 7 <= doc.size(); i++) {
        if (doc[i] == '<' && doc[i + 1] == '/' &&
            std::tolower(static_cast<unsigned char>(doc[i + 2])) == 't' &&
            std::tolower(static_cast<unsigned char>(doc[i + 3])) == 'i' &&
            std::tolower(static_cast<unsigned char>(doc[i + 4])) == 't' &&
            std::tolower(static_cast<unsigned char>(doc[i + 5])) == 'l' &&
            std::tolower(static_cast<unsigned char>(doc[i + 6])) == 'e') {
            end = i;
            break;
        }
    }
    if (end == std::string::npos) return "";
    return decodeEntities(doc.substr(start + 1, end - start - 1));
}

std::vector<HtmlBlock> HtmlView::extractBlocks(const std::string& html) {
    std::string doc = html;
    size_t c = 0;
    while ((c = doc.find("<!--", c)) != std::string::npos) {
        const size_t end = doc.find("-->", c);
        if (end == std::string::npos) { doc.erase(c); break; }
        doc.erase(c, end + 3 - c);
    }
    removeRegions(doc, "script");
    removeRegions(doc, "style");

    std::vector<HtmlBlock> blocks;
    std::string current;
    HtmlBlock::Kind currentKind = HtmlBlock::Kind::Paragraph;

    auto flush = [&]() {
        // Trim.
        size_t b = 0, e = current.size();
        while (b < e && std::isspace(static_cast<unsigned char>(current[b]))) b++;
        while (e > b && std::isspace(static_cast<unsigned char>(current[e - 1]))) e--;
        std::string text = decodeEntities(current.substr(b, e - b));
        // Collapse internal whitespace.
        std::string collapsed;
        bool prevSpace = false;
        for (char ch : text) {
            if (std::isspace(static_cast<unsigned char>(ch))) {
                if (!prevSpace) collapsed.push_back(' ');
                prevSpace = true;
            } else {
                collapsed.push_back(ch);
                prevSpace = false;
            }
        }
        if (!collapsed.empty()) {
            blocks.emplace_back(currentKind, collapsed);
        }
        current.clear();
    };

    bool inTag = false;
    std::string tagName;
    bool tagIsClosing = false;
    for (size_t i = 0; i < doc.size(); i++) {
        const char ch = doc[i];
        if (!inTag) {
            if (ch == '<') {
                inTag = true;
                tagName.clear();
                tagIsClosing = false;
                // Peek for '/'.
                if (i + 1 < doc.size() && doc[i + 1] == '/') tagIsClosing = true;
                continue;
            }
            current.push_back(ch);
            continue;
        }
        // Inside a tag.
        if (ch == '>') {
            inTag = false;
            const std::string lower = toLower(tagName);
            HtmlBlock::Kind kind;
            bool isTitle = false;
            if (blockBoundary(lower, kind, isTitle)) {
                if (tagIsClosing) {
                    flush();
                    currentKind = HtmlBlock::Kind::Paragraph;
                } else {
                    flush();
                    currentKind = kind;
                    if (isTitle && lower == "title") {
                        // Title content accumulates as a Title block.
                    }
                }
            } else if (lower == "head") {
                flush();
            }
            continue;
        }
        if (tagName.empty() && (ch == '/' || ch == '!' )) {
            tagIsClosing = tagIsClosing || ch == '/';
            continue;
        }
        if (tagName.size() < 16 && std::isalnum(static_cast<unsigned char>(ch))) {
            tagName.push_back(static_cast<char>(std::tolower(
                static_cast<unsigned char>(ch))));
        }
    }
    flush();
    return blocks;
}

} // namespace lethe
