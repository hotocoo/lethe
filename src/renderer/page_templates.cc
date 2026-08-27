// page_templates.cc - Lethe's internal pages (see header)

#include "renderer/page_templates.h"

namespace lethe {

namespace {

const char kCspMeta[] =
    "<meta http-equiv=\"Content-Security-Policy\" "
    "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">";

const char kBaseStyle[] =
    ":root{color-scheme:light dark}"
    "body{margin:0;font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',"
    "Roboto,Helvetica,Arial,sans-serif;background:#f7f7f8;color:#1c1c1e}"
    "@media(prefers-color-scheme:dark){body{background:#121214;color:#e6e6e8}}"
    "main{max-width:720px;margin:0 auto;padding:72px 32px}"
    "h1{font-size:28px;margin:0 0 12px;letter-spacing:-.01em}"
    "p{margin:0 0 12px}.url{word-break:break-all;opacity:.7;font-size:13px}"
    ".reason{padding:12px 16px;border-radius:8px;background:rgba(200,40,40,.08);"
    "border:1px solid rgba(200,40,40,.25)}"
    ".hint{opacity:.7;font-size:13px;margin-top:24px}";

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

std::string renderErrorPage(const std::string& url, const std::string& message) {
    std::string body = "<h1>This page could not be loaded</h1>";
    body += "<p class=\"url\">" + htmlEscape(url) + "</p>";
    body += "<p class=\"reason\">" + htmlEscape(message) + "</p>";
    body += "<p class=\"hint\">Check the address, then reload (⌘R).</p>";
    return page("Page failed to load", "", body);
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

std::string renderNewTabPage() {
    const char kStyle[] =
        "main{text-align:center;padding-top:22vh}"
        "h1{font-size:44px;font-weight:600;letter-spacing:-.02em}"
        ".sub{opacity:.6}kbd{font:inherit;padding:1px 6px;border-radius:5px;"
        "border:1px solid rgba(128,128,128,.4)}";
    std::string body = "<h1>Lethe</h1>";
    body += "<p class=\"sub\">Private by default. Type a URL or search in the "
            "address bar (<kbd>⌘L</kbd>).</p>";
    return page("New Tab", kStyle, body);
}

} // namespace lethe
