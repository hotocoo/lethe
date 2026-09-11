// LetheInternalPages.mm - see LetheInternalPages.h

#import "ui/mac/LetheInternalPages.h"

#import "ui/mac/LetheBookmarks.h"
#import "ui/mac/LetheHistory.h"

namespace {

NSString* Escape(NSString* value) {
    NSMutableString* out = [NSMutableString stringWithString:value ?: @""];
    [out replaceOccurrencesOfString:@"&" withString:@"&amp;" options:0
                              range:NSMakeRange(0, out.length)];
    [out replaceOccurrencesOfString:@"<" withString:@"&lt;" options:0
                              range:NSMakeRange(0, out.length)];
    [out replaceOccurrencesOfString:@">" withString:@"&gt;" options:0
                              range:NSMakeRange(0, out.length)];
    [out replaceOccurrencesOfString:@"\"" withString:@"&quot;" options:0
                              range:NSMakeRange(0, out.length)];
    return out;
}

NSString* Document(NSString* title, NSString* eyebrow, NSString* heading,
                   NSString* summary, NSString* body) {
    return [NSString stringWithFormat:
        @"<!doctype html><meta charset=\"utf-8\"><title>%@</title>%@"
        @"<main><p class=\"eyebrow\">%@</p><h1>%@</h1>"
        @"<p class=\"sub\">%@</p>%@</main>",
        Escape(title), LetheInternalPageStyle(), Escape(eyebrow), Escape(heading),
        Escape(summary), body];
}

NSString* RelativeDay(NSDate* date) {
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.dateStyle = NSDateFormatterFullStyle;
    formatter.timeStyle = NSDateFormatterNoStyle;
    formatter.doesRelativeDateFormatting = YES;
    return [formatter stringFromDate:date];
}

NSString* ClockTime(NSDate* date) {
    return [NSDateFormatter localizedStringFromDate:date
                                          dateStyle:NSDateFormatterNoStyle
                                          timeStyle:NSDateFormatterShortStyle];
}

}  // namespace

NSString* LetheInternalPageStyle(void) {
    // One accent (a desaturated teal that reads on both schemes), generous
    // measure, and a single hairline rhythm. Rows are laid out as a grid so
    // the title, origin and time land on the same optical columns instead of
    // wrapping into a ragged list.
    return @"<style>"
           @":root{color-scheme:light dark;"
           @"--ink:#16181a;--paper:#fbfbfa;--quiet:#5f666c;--line:rgba(22,24,26,.12);"
           @"--accent:#1f6f7a;--hover:rgba(31,111,122,.08)}"
           @"@media(prefers-color-scheme:dark){:root{"
           @"--ink:#e6e9ec;--paper:#131517;--quiet:#9aa2a8;--line:rgba(230,233,236,.14);"
           @"--accent:#6fc3cf;--hover:rgba(111,195,207,.10)}}"
           @"*{box-sizing:border-box}"
           @"body{margin:0;background:var(--paper);color:var(--ink);"
           @"font:15px/1.55 -apple-system,system-ui,'SF Pro Text',sans-serif;"
           @"-webkit-font-smoothing:antialiased}"
           @"main{max-width:860px;margin:0 auto;padding:72px 40px 96px}"
           @".eyebrow{margin:0 0 10px;font-size:11px;letter-spacing:.14em;"
           @"text-transform:uppercase;color:var(--quiet)}"
           @"h1{margin:0;font-size:40px;line-height:1.05;letter-spacing:-.022em;font-weight:640}"
           @"p.sub{margin:10px 0 40px;color:var(--quiet);font-size:14px}"
           @"h2{margin:36px 0 8px;font-size:12px;font-weight:620;letter-spacing:.08em;"
           @"text-transform:uppercase;color:var(--quiet)}"
           @"ul{list-style:none;margin:0;padding:0;border-top:1px solid var(--line)}"
           @"li{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 18px;"
           @"align-items:baseline;padding:13px 10px;margin:0 -10px;"
           @"border-bottom:1px solid var(--line);border-radius:8px;"
           @"transition:background-color .12s ease}"
           @"li:hover{background:var(--hover)}"
           @"li a{grid-column:1;color:var(--ink);text-decoration:none;font-weight:530;"
           @"overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}"
           @"li a:hover{color:var(--accent)}"
           @"li .u{grid-column:1;color:var(--quiet);font-size:12px;"
           @"font-family:ui-monospace,'SF Mono',Menlo,monospace;"
           @"overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
           @"li .t{grid-column:2;grid-row:1/span 2;color:var(--quiet);font-size:12px;"
           @"font-variant-numeric:tabular-nums}"
           @".empty{margin:28px 0;color:var(--quiet);font-size:14px}"
           @".rm{background:none;border:1px solid var(--line);border-radius:6px;"
           @"padding:3px 9px;color:var(--quiet);cursor:pointer;font:inherit;font-size:12px}"
           @".rm:hover{color:var(--accent);border-color:var(--accent)}"
           @"</style>";
}

NSString* LetheHistoryPageHTML(void) {
    NSArray<LetheHistoryEntry*>* entries = [[LetheHistory shared] allEntries];
    NSMutableString* rows = [NSMutableString string];
    NSString* currentDay = nil;
    for (LetheHistoryEntry* entry in entries) {
        NSString* day = RelativeDay(entry.visitedAt);
        if (![day isEqualToString:currentDay]) {
            if (currentDay) [rows appendString:@"</ul>"];
            [rows appendFormat:@"<h2>%@</h2><ul>", Escape(day)];
            currentDay = day;
        }
        NSString* title = entry.title.length ? entry.title : entry.url;
        [rows appendFormat:@"<li><a href=\"%@\">%@</a>"
                           @"<span class=\"u\">%@</span><span class=\"t\">%@</span></li>",
                           Escape(entry.url), Escape(title), Escape(entry.url),
                           Escape(ClockTime(entry.visitedAt))];
    }
    if (currentDay) [rows appendString:@"</ul>"];
    NSString* body = entries.count ? rows
                                   : @"<p class=\"empty\">No history recorded yet.</p>";
    NSString* summary = entries.count == 1
        ? @"1 page visited. History stays on this device."
        : [NSString stringWithFormat:@"%lu pages visited. History stays on this device.",
                                     (unsigned long)entries.count];
    return Document(@"History", @"Lethe", @"History", summary, body);
}

NSString* LetheBookmarksPageHTML(void) {
    NSArray<LetheBookmark*>* marks = [[LetheBookmarks shared] all];
    NSMutableString* rows = [NSMutableString string];
    if (marks.count) [rows appendString:@"<ul>"];
    for (LetheBookmark* mark in marks) {
        NSString* title = mark.title.length ? mark.title : mark.url;
        [rows appendFormat:@"<li><a href=\"%@\">%@</a>"
                           @"<span class=\"u\">%@</span><span class=\"t\">%@</span></li>",
                           Escape(mark.url), Escape(title), Escape(mark.url),
                           Escape(ClockTime(mark.addedAt))];
    }
    if (marks.count) [rows appendString:@"</ul>"];
    NSString* body = marks.count ? rows
                                 : @"<p class=\"empty\">No bookmarks yet. "
                                    "Press Command-D on a page to keep it.</p>";
    NSString* summary = marks.count == 1
        ? @"1 bookmark saved locally."
        : [NSString stringWithFormat:@"%lu bookmarks saved locally.",
                                     (unsigned long)marks.count];
    return Document(@"Bookmarks", @"Lethe", @"Bookmarks", summary, body);
}

NSString* LetheDataURLForHTML(NSString* html) {
    NSCharacterSet* allowed = [NSCharacterSet
        characterSetWithCharactersInString:
            @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~ \n\r"];
    NSString* encoded = [html stringByAddingPercentEncodingWithAllowedCharacters:allowed];
    return [@"data:text/html;charset=utf-8," stringByAppendingString:encoded ?: @""];
}
