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
    // Editorial rather than centred-splash: a masthead on the left edge, a
    // status rail that states what is actually protecting this tab, then the
    // user's own content. A new tab is read, not admired, so the type scale
    // carries the hierarchy and nothing bounces or glows.
    const char kStyle[] =
        ":root{--accent:#1f6f7a;--line:rgba(22,24,26,.13);--quiet:#5f666c}"
        "@media(prefers-color-scheme:dark){:root{--accent:#6fc3cf;"
        "--line:rgba(230,233,236,.15);--quiet:#98a0a6}}"
        "main{max-width:980px;padding:clamp(40px,9vh,88px) clamp(24px,5vw,56px) 64px}"
        ".mast{display:grid;grid-template-columns:minmax(0,1fr) auto;"
        "gap:16px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:18px}"
        "h1{font-size:clamp(38px,6vw,58px);line-height:.98;letter-spacing:-.035em;"
        "font-weight:660;margin:0}"
        ".sub{margin:10px 0 0;color:var(--quiet);font-size:14px;max-width:48ch}"
        "kbd{font:inherit;font-size:12px;padding:2px 7px;border-radius:6px;"
        "border:1px solid var(--line)}"
        ".rail{display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end;"
        "max-width:320px}"
        ".tag{font-size:11px;letter-spacing:.04em;text-transform:uppercase;"
        "color:var(--accent);border:1px solid var(--accent);border-radius:999px;"
        "padding:3px 9px;opacity:.85;white-space:nowrap}"
        ".cols{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(0,1fr);"
        "gap:clamp(24px,4vw,56px);margin-top:36px}"
        "h2{font-size:11px;font-weight:620;letter-spacing:.11em;"
        "text-transform:uppercase;color:var(--quiet);margin:0 0 10px}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));"
        "gap:2px}"
        ".tile{display:block;padding:10px 12px;margin:0 -12px;border-radius:8px;"
        "text-decoration:none;color:inherit;transition:background-color .12s ease}"
        ".tile:hover{background:color-mix(in oklab,var(--accent) 10%,transparent)}"
        ".tile .t{font-weight:540;font-size:14px;display:block;white-space:nowrap;"
        "overflow:hidden;text-overflow:ellipsis}"
        ".tile .u{font-size:11px;color:var(--quiet);display:block;margin-top:2px;"
        "white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"
        "font-family:ui-monospace,'SF Mono',Menlo,monospace}"
        ".empty{color:var(--quiet);font-size:13px;margin:0}"
        ".notes{margin-top:4px;border-top:1px solid var(--line)}"
        ".note{display:grid;grid-template-columns:minmax(0,1fr);gap:2px;"
        "padding:12px 0;border-bottom:1px solid var(--line)}"
        ".note strong{font-size:13px;font-weight:600}"
        ".note span{font-size:12.5px;color:var(--quiet);line-height:1.5}"
        ".foot{margin:40px 0 0;color:var(--quiet);font-size:12px}"
        "@media(max-width:760px){.cols{grid-template-columns:1fr;gap:28px}"
        ".mast{grid-template-columns:1fr}.rail{justify-content:flex-start;max-width:none}}";

    std::string body =
        "<section class=\"mast\"><div><h1>Lethe</h1>"
        "<p class=\"sub\">Private by default. Type an address or a search "
        "(<kbd>⌘L</kbd>).</p></div>"
        "<div class=\"rail\">"
        "<span class=\"tag\">HTTPS-first</span>"
        "<span class=\"tag\">DNS-over-HTTPS</span>"
        "<span class=\"tag\">Tracker blocking</span>"
        "<span class=\"tag\">Threat scanner</span>"
        "<span class=\"tag\">Private-network guard</span>"
        "</div></section>";

    auto esc = [](const std::string& v) { return htmlEscape(v); };
    auto tiles = [&esc](const std::vector<SpeedDialItem>& items,
                        const std::string& heading) {
        std::string out = "<h2>" + heading + "</h2>";
        if (items.empty()) {
            out += "<p class=\"empty\">Nothing here yet.</p>";
            return out;
        }
        out += "<div class=\"grid\">";
        for (const auto& it : items) {
            out += "<a class=\"tile\" href=\"" + esc(it.url) + "\"><span class=\"t\">" +
                   esc(it.title) + "</span><span class=\"u\">" + esc(it.url) +
                   "</span></a>";
        }
        out += "</div>";
        return out;
    };

    body += "<div class=\"cols\"><div>";
    body += tiles(bookmarks, "Bookmarks");
    body += "<div style=\"height:28px\"></div>";
    body += tiles(recent, "Recent");
    body += "</div><aside><h2>This tab</h2><div class=\"notes\">"
            "<div class=\"note\"><strong>Network policy</strong><span>Every "
            "navigation resolves over DNS-over-HTTPS, refuses private-network "
            "destinations, and rides Lethe's policy proxy.</span></div>"
            "<div class=\"note\"><strong>Threat scanning</strong><span>Sites and "
            "downloads are checked locally, on this machine. Nothing is sent to "
            "a reputation service.</span></div>"
            "<div class=\"note\"><strong>Site data</strong><span>History, "
            "bookmarks and cookies stay in Lethe's own profile, and Oblivion "
            "windows keep none of it.</span></div>"
            "</div></aside></div>";
    body += "<p class=\"foot\">A controlled, private path to the web.</p>";
    return page("New Tab", kStyle, body);
}

} // namespace lethe
