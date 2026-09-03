// page_templates.cc - Lethe's internal pages (see header)

#include "renderer/page_templates.h"

#include "browser/url_input.h"

namespace lethe {

namespace {

const char kCspMeta[] =
    "<meta http-equiv=\"Content-Security-Policy\" "
    "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">";

// The "Lethe Quiet" style for internal pages: mirrors src/ui/mac/
// LetheDesign.h (ink on paper, hairlines, one cold accent). Keep in sync.
const char kBaseStyle[] =
    ":root{color-scheme:light dark}"
    "body{margin:0;font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',"
    "Roboto,Helvetica,Arial,sans-serif;background:#fafafa;color:#1b1e21}"
    "@media(prefers-color-scheme:dark){body{background:#16181a;color:#dcdfe2}}"
    "main{max-width:720px;margin:0 auto;padding:72px 32px}"
    "h1{font-size:26px;font-weight:600;margin:0 0 12px;letter-spacing:-.01em}"
    "p{margin:0 0 12px}.url{word-break:break-all;opacity:.6;font-size:13px}"
    "a{color:#295770;text-decoration:none}"
    "@media(prefers-color-scheme:dark){a{color:#8cbad0}}"
    "a:hover{text-decoration:underline}"
    "hr{border:0;border-top:1px solid rgba(128,128,128,.25);margin:20px 0}"
    ".reason{padding:12px 16px;background:rgba(200,40,40,.06);"
    "border-left:2px solid rgba(200,40,40,.55)}"
    ".hint{opacity:.6;font-size:13px;margin-top:24px}";

std::string page(const std::string& title, const std::string& extraStyle,
                 const std::string& body) {
    std::string out = "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">";
    out += kCspMeta;
    out += "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">";
    out += "<title>" + htmlEscape(title) + "</title><style>" + kBaseStyle +
           extraStyle + "</style></head><body><main>" + body +
           "</main></body></html>";
    return out;
}

} // namespace

std::string htmlEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 16);
    for (char c : in) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string renderBlockPage(const std::string& url, const std::string& reason) {
    std::string body = "<h1>Blocked by Lethe policy</h1>";
    body += "<p class=\"url\">" + htmlEscape(url) + "</p>";
    body += "<p class=\"reason\">" + htmlEscape(reason) + "</p>";
    body += "<p class=\"hint\">Lethe fails closed: destinations that cannot be "
            "resolved over secure DNS, that land on private networks, or that "
            "the VPN policy refuses are never contacted.</p>";
    return page("Blocked", "", body);
}

std::string renderErrorPage(const std::string& url, const std::string& message,
                            const std::string& httpFallback) {
    std::string body = "<h1>This page could not be loaded</h1>";
    body += "<p class=\"url\">" + htmlEscape(url) + "</p>";
    body += "<p class=\"reason\">" + htmlEscape(message) + "</p>";
    if (!httpFallback.empty()) {
        body += "<p class=\"hint\">Lethe tried the encrypted (https) version of "
                "this address first and it did not answer. The plain http "
                "version is NOT encrypted: anyone on the network can read and "
                "change it.</p>";
        body += "<p><a class=\"fallback\" href=\"" +
                htmlEscape(httpFallbackActionUrl(httpFallback)) +
                "\">Continue to " + htmlEscape(httpFallback) + " (not encrypted)</a></p>";
    } else {
        body += "<p class=\"hint\">Check the address, then reload (⌘R).</p>";
    }
    return page("Page failed to load", ".fallback{color:#b3261e}", body);
}

std::string renderReaderPage(const std::string& url,
                             const std::vector<HtmlBlock>& blocks) {
    const char kReaderStyle[] =
        "main{max-width:680px;padding:56px 24px;font-size:18px;line-height:1.7}"
        "h1.title{font-size:34px;line-height:1.2;margin:0 0 8px}"
        "h2{font-size:26px;margin:32px 0 8px}h3{font-size:22px;margin:28px 0 8px}"
        "h4{font-size:19px;margin:24px 0 8px}ul{padding-left:24px}"
        "p{margin:0 0 18px}.source{margin-bottom:32px}";
    std::string body;
    std::string title = "Reader";
    bool inList = false;
    auto closeList = [&]() { if (inList) { body += "</ul>"; inList = false; } };
    body += "<p class=\"url source\">" + htmlEscape(url) + "</p>";
    for (const auto& b : blocks) {
        const std::string t = htmlEscape(b.text);
        switch (b.kind) {
            case HtmlBlock::Kind::Title:
                closeList(); title = b.text;
                body += "<h1 class=\"title\">" + t + "</h1>"; break;
            case HtmlBlock::Kind::Heading1:
                closeList(); body += "<h2>" + t + "</h2>"; break;
            case HtmlBlock::Kind::Heading2:
                closeList(); body += "<h3>" + t + "</h3>"; break;
            case HtmlBlock::Kind::Heading3:
                closeList(); body += "<h4>" + t + "</h4>"; break;
            case HtmlBlock::Kind::ListItem:
                if (!inList) { body += "<ul>"; inList = true; }
                body += "<li>" + t + "</li>"; break;
            case HtmlBlock::Kind::Paragraph:
                closeList(); body += "<p>" + t + "</p>"; break;
        }
    }
    closeList();
    if (blocks.empty()) body += "<p class=\"hint\">No readable text found.</p>";
    return page(title, kReaderStyle, body);
}

std::string renderNewTabPage(const std::vector<SpeedDialItem>& recent,
                             const std::vector<SpeedDialItem>& bookmarks) {
    const char kStyle[] =
        "main{text-align:center;padding:64px 32px 24px}"
        "h1{font-size:34px;font-weight:600;letter-spacing:-.02em;margin:0 0 6px}"
        ".sub{opacity:.55;margin:0 0 40px}"
        "kbd{font:inherit;padding:1px 6px;border-radius:5px;"
        "border:1px solid rgba(128,128,128,.4)}"
        "h2{font-size:12px;font-weight:600;opacity:.55;text-transform:uppercase;"
        "letter-spacing:.08em;margin:28px 0 10px;text-align:left}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));"
        "gap:4px 12px;text-align:left}"
        ".tile{display:block;padding:8px 10px;border-radius:6px;text-decoration:none;color:inherit}"
        ".tile:hover{background:rgba(127,127,127,.10)}"
        ".tile .t{font-weight:500;font-size:14px;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}"
        ".tile .u{font-size:11px;opacity:.5;display:block;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:ui-monospace,Menlo,monospace}"
        ".empty{opacity:.5;font-style:italic;text-align:left}"
        ".shield{max-width:560px;margin:0 auto;text-align:left;"
        "border:1px solid rgba(128,128,128,.22);border-radius:12px;padding:18px 20px}"
        ".shield p{margin:7px 0;opacity:.72}"
        ".ok{font-weight:600}"
        ".hint{margin-top:28px;opacity:.55}";
    std::string body = "<h1>Lethe</h1>";
    body += "<p class=\"sub\">Private by default. Type a URL or search in the "
            "address bar (<kbd>⌘L</kbd>).</p>";
    body += "<section class=\"shield\">"
            "<p class=\"ok\">Network policy enforced</p>"
            "<p>HTTPS-first, DNS-over-HTTPS, private-network isolation, and "
            "authenticated transport policy protect every navigation.</p>"
            "<p class=\"ok\">Ephemeral site data</p>"
            "<p>Browsing history, bookmarks, and session restore are available "
            "from the browser menus and remain under Lethe's local profile.</p>"
            "<p class=\"ok\">Built-in privacy controls</p>"
            "<p>Tracker blocking, WebRTC protection, fingerprint reduction, "
            "and Oblivion windows are available in Settings.</p>";
    auto esc = [](const std::string& s) {
        std::string out; out.reserve(s.size());
        for (char c : s) switch (c) { case '<': out += "&lt;"; break; case '>': out += "&gt;"; break; case '&': out += "&amp;"; break; case '"': out += "&quot;"; break; default: out += c; }
        return out;
    };
    auto tiles = [&](const std::vector<SpeedDialItem>& items, const char* heading) {
        std::string out = "<h2>"; out += heading; out += "</h2>";
        if (items.empty()) { out += "<p class=\"empty\">Nothing here yet.</p>"; return out; }
        out += "<div class=\"grid\">";
        for (const auto& it : items) out += "<a class=\"tile\" href=\"" + esc(it.url) + "\"><span class=\"t\">" + esc(it.title) + "</span><span class=\"u\">" + esc(it.url) + "</span></a>";
        out += "</div>";
        return out;
    };
    body += tiles(bookmarks, "Bookmarks");
    body += tiles(recent, "Recent");
    body += "</section><p class=\"hint\">Lethe exists to give Aletheia a controlled, private path to the web.</p>";
    return page("New Tab", kStyle, body);
}

} // namespace lethe
