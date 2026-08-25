// hsts_cache.cc - In-memory HSTS (RFC 6797) policy store.
//
// See include/security/hsts_cache.h for the semantics. This translation
// unit holds no global state: every Engine owns one cache, and the cache
// never touches the filesystem (privacy posture matches the cookie jar).

#include "security/hsts_cache.h"

#include <algorithm>
#include <cctype>

namespace lethe {

namespace {

std::string toLowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string trimCopy(const std::string& s) {
    const size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    const size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

} // namespace

bool HstsCache::parseStsHeader(const std::string& value,
                               std::chrono::seconds& maxAge,
                               bool& includeSubDomains) {
    // field-value = directive *( ";" directive ); directives are
    // case-insensitive name[=value] tokens separated by ';'. max-age is
    // required and must parse as 1*DIGIT; an unparsable or missing
    // max-age means the WHOLE header is ignored (RFC 6797 section 11.3).
    // Unknown directives are ignored.
    includeSubDomains = false;
    bool haveMaxAge = false;
    long long parsed = -1;
    size_t pos = 0;
    while (pos <= value.size()) {
        size_t semi = value.find(';', pos);
        if (semi == std::string::npos) semi = value.size();
        std::string token = trimCopy(value.substr(pos, semi - pos));
        pos = semi + 1;

        if (token.empty()) continue;
        std::string name = token;
        std::string dirValue;
        const size_t eq = token.find('=');
        if (eq != std::string::npos) {
            name = trimCopy(token.substr(0, eq));
            dirValue = trimCopy(token.substr(eq + 1));
        }
        name = toLowerCopy(name);

        if (name == "max-age") {
            // RFC 6797 grammar: 1*DIGIT, no sign, no whitespace inside.
            if (dirValue.empty() ||
                !std::all_of(dirValue.begin(), dirValue.end(),
                             [](unsigned char c) { return std::isdigit(c); })) {
                return false;
            }
            // Cap digit count so stoll can never overflow (and throw).
            if (dirValue.size() > 12) return false;
            haveMaxAge = true;
            parsed = std::stoll(dirValue, nullptr, 10);
        } else if (name == "includesubdomains") {
            includeSubDomains = true;
        }
        if (semi == value.size()) break;
    }

    if (!haveMaxAge) return false;
    maxAge = std::chrono::seconds(parsed);
    return true;
}

std::string HstsCache::normalizeHost(const std::string& host) {
    std::string out = toLowerCopy(trimCopy(host));
    // A single trailing dot on a fully-qualified name carries no policy
    // identity of its own.
    if (out.size() > 1 && out.back() == '.') out.pop_back();
    return out;
}

bool HstsCache::isIpLiteral(const std::string& host) {
    // IPv4 dotted quad or anything containing ':' (IPv6 literal, optionally
    // bracketed). IP-literal hosts cannot carry an HSTS identity.
    if (host.empty() || host.find(':') != std::string::npos) {
        return !host.empty();
    }
    size_t digits = 0, dots = 0;
    bool allDigitsOrDots = true;
    for (const char c : host) {
        if (c == '.') { dots++; continue; }
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            allDigitsOrDots = false;
            break;
        }
        digits++;
    }
    return allDigitsOrDots && dots > 0 && digits > 0;
}

void HstsCache::record(const std::string& host,
                       std::chrono::seconds maxAge,
                       bool includeSubDomains,
                       std::chrono::steady_clock::time_point now) {
    const std::string key = normalizeHost(host);
    if (key.empty() || isIpLiteral(key)) return;

    if (maxAge <= std::chrono::seconds::zero()) {
        entries_.erase(key); // max-age=0 revokes the policy
        return;
    }

    Entry entry;
    entry.expires = now + maxAge;
    entry.includeSubDomains = includeSubDomains;

    const auto it = entries_.find(key);
    if (it != entries_.end()) {
        entry.seq = it->second.seq; // refresh keeps the insertion slot
        it->second = entry;
        return;
    }

    entry.seq = nextSeq_++;
    // Bound memory: evict the least-recently-recorded policy first.
    while (entries_.size() >= kMaxEntries) {
        const auto oldest = std::min_element(
            entries_.begin(), entries_.end(),
            [](const auto& a, const auto& b) {
                return a.second.seq < b.second.seq;
            });
        entries_.erase(oldest);
    }
    entries_.emplace(key, entry);
}

bool HstsCache::shouldUpgrade(const std::string& host,
                              std::chrono::steady_clock::time_point now) const {
    const std::string key = normalizeHost(host);
    if (key.empty() || isIpLiteral(key)) return false;

    // Exact match: any live policy upgrades.
    const auto exact = entries_.find(key);
    if (exact != entries_.end() && exact->second.expires > now) {
        return true;
    }

    // Subdomains upgrade only under a live includeSubDomains ancestor:
    // for a.b.example.com probe b.example.com, then example.com, then com.
    size_t dot = key.find('.');
    while (dot != std::string::npos && dot + 1 < key.size()) {
        const auto anc = entries_.find(key.substr(dot + 1));
        if (anc != entries_.end() && anc->second.expires > now &&
            anc->second.includeSubDomains) {
            return true;
        }
        dot = key.find('.', dot + 1);
    }
    return false;
}

size_t HstsCache::size(std::chrono::steady_clock::time_point now) const {
    size_t live = 0;
    for (const auto& kv : entries_) {
        if (kv.second.expires > now) live++;
    }
    return live;
}

void HstsCache::clear() {
    entries_.clear();
    nextSeq_ = 0;
}

} // namespace lethe
