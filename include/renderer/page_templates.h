#ifndef LETHE_RENDERER_PAGE_TEMPLATES_H
#define LETHE_RENDERER_PAGE_TEMPLATES_H

// page_templates.h - Lethe's internal pages as self-contained HTML
//
// Every shell shows the same block / error / reader pages. All dynamic
// text is HTML-escaped; every page carries a script-free CSP meta tag so
// even a hostile URL or server message can never execute in the view.

#include <string>
#include <vector>

#include "renderer/html_view.h"

namespace lethe {

std::string htmlEscape(const std::string& in);

// Navigation refused by policy (DoH failure, private network, VPN rule...).
std::string renderBlockPage(const std::string& url, const std::string& reason);

// Load failed (network error, TLS failure, DNS...). When \p httpFallback is
// non-empty the page offers ONE explicit link that allow-lists the host for
// plaintext and loads it (HTTPS-first upgrade failed).
std::string renderErrorPage(const std::string& url, const std::string& message,
                            const std::string& httpFallback = "");

// Reader view of extracted blocks; \p url is shown as the source line.
std::string renderReaderPage(const std::string& url,
                             const std::vector<HtmlBlock>& blocks);

// Start page shown in a fresh tab. Each list is (title, url) pairs;
// an empty list omits the section.
struct SpeedDialItem { std::string title; std::string url; };
std::string renderNewTabPage(const std::vector<SpeedDialItem>& recent = {},
                             const std::vector<SpeedDialItem>& bookmarks = {});

} // namespace lethe

#endif // LETHE_RENDERER_PAGE_TEMPLATES_H
