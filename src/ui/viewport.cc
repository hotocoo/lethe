// viewport.cc - Web content viewport (reader-mode Cairo renderer)
//
// Fetches through the engine's HTTP client (inheriting DoH, VPN policy and
// TLS hardening) and renders HTML as clean structured text: headings,
// paragraphs, and list items word-wrapped to the window. No JavaScript,
// no CSS, no remote assets - the minimum rendering surface that cannot
// track the reader or run attacker code.

#include "viewport.h"
#include "renderer/html_view.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

namespace lethe {

namespace {

// Per-kind typography.
struct Style {
    double size;
    bool bold;
};

Style styleFor(HtmlBlock::Kind kind) {
    switch (kind) {
        case HtmlBlock::Kind::Title:     return {24.0, true};
        case HtmlBlock::Kind::Heading1:  return {21.0, true};
        case HtmlBlock::Kind::Heading2:  return {18.0, true};
        case HtmlBlock::Kind::Heading3:  return {15.5, true};
        case HtmlBlock::Kind::ListItem:  return {13.0, false};
        case HtmlBlock::Kind::Paragraph: return {13.0, false};
    }
    return {13.0, false};
}

constexpr double kLineSpacing = 1.5;
constexpr double kMargin = 24.0;
constexpr size_t kMaxBlocksDrawn = 400;
constexpr double kMaxDrawY = 20000.0; // hard cap on painted lines

// Word-wrap text into lines no wider than width; draw them starting at y.
// Returns the y position after the last line.
double drawWrapped(cairo_t* cr, const std::string& text,
                   double x, double y, double width,
                   double size, bool bold) {
    cairo_select_font_face(cr, "Sans",
                           CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD
                                : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);

    cairo_text_extents_t extents;
    std::string line;
    auto measure = [&](const std::string& s) {
        cairo_text_extents(cr, s.c_str(), &extents);
        return extents.width;
    };

    size_t start = 0;
    while (start <= text.size() && y < kMaxDrawY) {
        // Take the next word.
        size_t end = text.find(' ', start);
        if (end == std::string::npos) end = text.size();
        const std::string word = text.substr(start, end - start);

        std::string candidate = line.empty() ? word : line + " " + word;
        if (!line.empty() && measure(candidate) > width) {
            cairo_move_to(cr, x, y);
            cairo_show_text(cr, line.c_str());
            y += size * kLineSpacing;
            line = word;
        } else {
            line = candidate;
        }

        if (end == text.size()) break;
        start = end + 1;
    }
    if (!line.empty() && y < kMaxDrawY) {
        cairo_move_to(cr, x, y);
        cairo_show_text(cr, line.c_str());
        y += size * kLineSpacing;
    }
    return y;
}

} // namespace

Viewport::Viewport(Engine* engine) : engine_(engine), webView_(nullptr),
                                     currentUrl_(""), isLoading_(false) {
}

Viewport::~Viewport() = default;

GtkWidget* Viewport::create() {
    webView_ = gtk_drawing_area_new();
    gtk_widget_set_hexpand(webView_, TRUE);
    gtk_widget_set_vexpand(webView_, TRUE);
    g_signal_connect(webView_, "draw", G_CALLBACK(onDraw), this);
    return webView_;
}

void Viewport::loadURL(const std::string& url) {
    if (!engine_ || !engine_->tabManager() || !engine_->httpClient()) return;

    currentUrl_ = url;
    isLoading_ = true;
    gtk_widget_queue_draw(webView_);

    int activeTab = engine_->tabManager()->getActiveTab();
    engine_->tabManager()->navigate(activeTab, url);
    engine_->tabManager()->setTabLoading(activeTab, true);
    engine_->history()->addEntry(url);

    HttpRequest req;
    req.url = url;
    req.method = HttpMethod::GET;

    HttpResponse resp = engine_->httpClient()->sendRequest(req);

    if (resp.success && resp.statusCode == 200) {
        std::string content(resp.body.begin(), resp.body.end());
        showContent(content, "text/html");
    } else {
        showError(resp.error.empty() ? "Failed to load page" : resp.error);
    }

    isLoading_ = false;
    engine_->tabManager()->setTabLoading(activeTab, false);
    gtk_widget_queue_draw(webView_);
}

void Viewport::stop() {
    isLoading_ = false;
}

void Viewport::reload() {
    if (!currentUrl_.empty()) {
        loadURL(currentUrl_);
    }
}

void Viewport::showContent(const std::string& content, const std::string& mimeType) {
    errorText_.clear();
    if (mimeType == "text/html" || mimeType == "application/xhtml+xml") {
        blocks_ = HtmlView::extractBlocks(content);
    } else {
        blocks_.clear();
        blocks_.emplace_back(HtmlBlock::Kind::Paragraph, content);
    }
    gtk_widget_queue_draw(webView_);
}

void Viewport::showError(const std::string& error) {
    std::cout << "[lethe] Error: " << error << std::endl;
    blocks_.clear();
    errorText_ = error;
    gtk_widget_queue_draw(webView_);
}

bool Viewport::onDraw(GtkWidget* widget, cairo_t* cr, gpointer data) {
    Viewport* self = static_cast<Viewport*>(data);

    GtkAllocation alloc;
    gtk_widget_get_allocation(widget, &alloc);
    const double width = std::max(200.0, static_cast<double>(alloc.width)) - 2 * kMargin;

    // Background.
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_paint(cr);

    double y = kMargin + 12.0;
    cairo_set_source_rgb(cr, 0.12, 0.12, 0.14);

    if (self->isLoading_) {
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL,
                               CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 15);
        cairo_move_to(cr, kMargin, y + 10);
        cairo_show_text(cr, "Loading...");
    } else if (!self->errorText_.empty()) {
        cairo_set_source_rgb(cr, 0.65, 0.15, 0.15);
        y = drawWrapped(cr, "Failed to load page", kMargin, y, width, 20.0, true);
        cairo_set_source_rgb(cr, 0.25, 0.25, 0.28);
        drawWrapped(cr, self->errorText_, kMargin, y + 8.0, width, 13.0, false);
    } else if (!self->blocks_.empty()) {
        size_t drawn = 0;
        double prevKind = -1;
        for (const auto& block : self->blocks_) {
            if (drawn >= kMaxBlocksDrawn || y > alloc.height + 40.0) break;
            const Style st = styleFor(block.kind);
            const std::string text = block.kind == HtmlBlock::Kind::ListItem
                ? "\xE2\x80\xA2 " + block.text
                : block.text;
            // Extra spacing before headings.
            if (static_cast<double>(block.kind) != prevKind &&
                block.kind != HtmlBlock::Kind::Paragraph) {
                y += 10.0;
            }
            cairo_set_source_rgb(cr, 0.12, 0.12, 0.14);
            y = drawWrapped(cr, text, kMargin, y, width, st.size, st.bold);
            y += 6.0;
            prevKind = static_cast<double>(block.kind);
            drawn++;
        }
    } else if (!self->currentUrl_.empty()) {
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL,
                               CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 13);
        cairo_move_to(cr, kMargin, y + 10);
        cairo_show_text(cr, self->currentUrl_.c_str());
    } else {
        cairo_set_source_rgb(cr, 0.1, 0.1, 0.12);
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL,
                               CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 24);
        cairo_move_to(cr, 100, 100);
        cairo_show_text(cr, "Lethe Browser");
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL,
                               CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 13);
        cairo_move_to(cr, 100, 132);
        cairo_show_text(cr, "Enter a URL to begin browsing");
    }

    return TRUE;
}

} // namespace lethe
