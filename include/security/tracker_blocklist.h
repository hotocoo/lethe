#ifndef LETHE_SECURITY_TRACKER_BLOCKLIST_H
#define LETHE_SECURITY_TRACKER_BLOCKLIST_H

// tracker_blocklist.h - built-in third-party tracker protection
//
// The curated list in browser/blocklist/trackers.txt is compiled into the
// binary and turned into WebKit content-blocker rules (the JSON dialect
// shared by WKContentRuleList on macOS and WebKitUserContentFilterStore on
// Linux). Rules match third-party requests to the listed registrable
// domains and their subdomains, every resource type, and block them
// before any bytes leave the engine. First-party requests are never
// touched, so a site keeps working on its own domain.
//
// Honest scope: a few hundred advertising / analytics / identity hosts,
// not EasyList. docs/BENCHMARKS.md measures what it removes.

#include <string>
#include <vector>

namespace lethe {

struct TrackerBlocklist {
    // Registrable domains (lowercase, no scheme, no wildcard).
    std::vector<std::string> domains;
    // Path-scoped patterns "domain/path-prefix" for hosts that also serve
    // legitimate content (e.g. facebook.com/tr).
    std::vector<std::string> pathPatterns;
};

// Parse the list format: one entry per line, '#' comments, blanks ignored,
// duplicates collapsed, entries lowercased. Never throws.
TrackerBlocklist parseTrackerBlocklist(const std::string& text);

// The built-in list compiled from browser/blocklist/trackers.txt.
const TrackerBlocklist& builtinTrackerBlocklist();

// WebKit content-blocker JSON for the list. Each domain becomes one rule:
//   {"trigger":{"url-filter":"^https?://([^/]+\\.)?example\\.com[/:]",
//               "load-type":["third-party"]},"action":{"type":"block"}}
std::string trackerContentRulesJson(const TrackerBlocklist& list);

// Stable identifier for the compiled rule store (changes when the list
// changes so engines recompile instead of serving a stale cache).
std::string trackerRulesIdentifier(const TrackerBlocklist& list);

// Escape a string for use inside a WebKit url-filter regular expression.
std::string regexEscape(const std::string& in);

} // namespace lethe

#endif // LETHE_SECURITY_TRACKER_BLOCKLIST_H
