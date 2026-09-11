// site_reputation.cc - see include/security/site_reputation.h

#include "security/site_reputation.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <vector>

#include "security/file_scanner.h"

namespace lethe {
namespace {

// Brands whose login pages are the standard phishing targets. This list is
// short on purpose: every entry costs false positives on legitimate lookalike
// domains, so it holds only names that are both widely phished and unlikely
// to collide with an unrelated business.
const char* const kProtectedBrands[] = {
    "apple.com",     "icloud.com",   "google.com",    "gmail.com",
    "microsoft.com", "outlook.com",  "office.com",    "paypal.com",
    "amazon.com",    "facebook.com", "instagram.com", "netflix.com",
    "binance.com",   "coinbase.com", "metamask.io",   "github.com",
    "dropbox.com",   "linkedin.com", "whatsapp.com",  "chase.com",
};

// Free/abused TLDs with historically high phishing density. Presence alone
// is a weak signal and scores accordingly.
const char* const kHighRiskTlds[] = {"zip", "mov", "tk", "ml", "ga", "cf",
                                     "gq", "top", "xyz", "click", "country",
                                     "kim", "work", "party", "review"};

const char* const kUrlShorteners[] = {"bit.ly", "tinyurl.com", "t.co",
                                      "goo.gl", "ow.ly", "is.gd", "buff.ly",
                                      "rebrand.ly", "cutt.ly", "shorturl.at"};

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

struct ParsedUrl {
    std::string scheme;
    std::string userInfo;
    std::string host;
    std::string port;
    std::string path;
    std::string query;
    bool valid = false;
};

ParsedUrl parseUrl(const std::string& url) {
    ParsedUrl parsed;
    const size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        // Scheme-relative or opaque (data:, javascript:, blob:).
        const size_t colon = url.find(':');
        if (colon == std::string::npos) return parsed;
        parsed.scheme = toLower(url.substr(0, colon));
        parsed.path = url.substr(colon + 1);
        parsed.valid = true;
        return parsed;
    }
    parsed.scheme = toLower(url.substr(0, schemeEnd));
    size_t cursor = schemeEnd + 3;
    const size_t authorityEnd = url.find_first_of("/?#", cursor);
    std::string authority = authorityEnd == std::string::npos
                                ? url.substr(cursor)
                                : url.substr(cursor, authorityEnd - cursor);
    const size_t at = authority.find_last_of('@');
    if (at != std::string::npos) {
        parsed.userInfo = authority.substr(0, at);
        authority = authority.substr(at + 1);
    }
    const size_t colon = authority.find_last_of(':');
    if (colon != std::string::npos && authority.find(']') == std::string::npos) {
        parsed.port = authority.substr(colon + 1);
        authority = authority.substr(0, colon);
    }
    parsed.host = toLower(authority);
    if (authorityEnd != std::string::npos) {
        const std::string rest = url.substr(authorityEnd);
        const size_t question = rest.find('?');
        parsed.path = question == std::string::npos ? rest : rest.substr(0, question);
        if (question != std::string::npos) parsed.query = rest.substr(question + 1);
    }
    parsed.valid = !parsed.host.empty();
    return parsed;
}

bool isIpLiteral(const std::string& host) {
    if (host.empty()) return false;
    if (host.front() == '[') return true;   // IPv6 literal
    int dots = 0;
    for (char c : host) {
        if (c == '.') { dots++; continue; }
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    return dots == 3;
}

// Everything after the first label, e.g. "login.apple.com.evil.ru" -> the
// registrable part is approximated as the last two labels. A full public
// suffix list would be more precise; the approximation is only used for
// "is the brand in the registrable part or merely in a subdomain?"
std::string registrableSuffix(const std::string& host) {
    std::vector<std::string> labels;
    size_t start = 0;
    while (start <= host.size()) {
        const size_t dot = host.find('.', start);
        labels.push_back(host.substr(start, dot == std::string::npos
                                                ? std::string::npos
                                                : dot - start));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    if (labels.size() < 2) return host;
    return labels[labels.size() - 2] + "." + labels.back();
}

std::string tldOf(const std::string& host) {
    const size_t dot = host.find_last_of('.');
    return dot == std::string::npos ? std::string() : host.substr(dot + 1);
}

bool inList(const std::string& value, const char* const* list, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (value == list[i]) return true;
    return false;
}

// Strips characters that only exist to defeat string comparison: the
// "rn"/"m" and "l"/"1" style substitutions used in typosquats.
std::string canonicalConfusables(const std::string& host) {
    std::string out;
    out.reserve(host.size());
    for (size_t i = 0; i < host.size(); ++i) {
        const char c = host[i];
        if (c == '1' || c == '|') { out.push_back('l'); continue; }
        if (c == '0') { out.push_back('o'); continue; }
        if (c == '5') { out.push_back('s'); continue; }
        if (c == '-' || c == '_') continue;
        if (c == 'r' && i + 1 < host.size() && host[i + 1] == 'n') {
            out.push_back('m');
            ++i;
            continue;
        }
        out.push_back(c);
    }
    return out;
}

}  // namespace

size_t editDistance(const std::string& a, const std::string& b, size_t limit) {
    if (a == b) return 0;
    const size_t n = a.size(), m = b.size();
    if (n > m + limit || m > n + limit) return limit + 1;
    std::vector<size_t> previous(m + 1), current(m + 1);
    for (size_t j = 0; j <= m; ++j) previous[j] = j;
    for (size_t i = 1; i <= n; ++i) {
        current[0] = i;
        size_t rowMin = current[0];
        for (size_t j = 1; j <= m; ++j) {
            const size_t cost = a[i - 1] == b[j - 1] ? 0 : 1;
            current[j] = std::min({previous[j] + 1, current[j - 1] + 1,
                                   previous[j - 1] + cost});
            rowMin = std::min(rowMin, current[j]);
        }
        if (rowMin > limit) return limit + 1;
        previous = current;
    }
    return previous[m];
}

bool looksLikeImpersonation(const std::string& host, std::string* impersonated) {
    const std::string registrable = registrableSuffix(host);
    for (const char* brand : kProtectedBrands) {
        if (registrable == brand) return false;   // the real thing
    }
    const std::string canonical = canonicalConfusables(registrable);
    for (const char* brandC : kProtectedBrands) {
        const std::string brand(brandC);
        // The brand appears as a label somewhere other than the registrable
        // part: "apple.com.secure-login.ru".
        const std::string brandLabel = brand.substr(0, brand.find('.'));
        if (host.find("." + brandLabel + ".") != std::string::npos ||
            host.rfind(brandLabel + ".", 0) == 0) {
            if (registrable.rfind(brandLabel + ".", 0) != 0) {
                if (impersonated) *impersonated = brand;
                return true;
            }
        }
        // Typosquat: within one edit of the real registrable domain after
        // folding the common visual substitutions.
        // Folding the confusables can make a squat identical to the brand
        // ("paypa1.com" -> "paypal.com"); that is the strongest form of the
        // signal, not a reason to skip it. The literal registrable domain
        // was already checked against the brand list above, so an exact
        // canonical match here means the host only *looks* like the brand.
        const std::string canonicalBrand = canonicalConfusables(brand);
        if (editDistance(canonical, canonicalBrand, 1) <= 1) {
            if (impersonated) *impersonated = brand;
            return true;
        }
    }
    return false;
}

ThreatReport assessUrl(const std::string& url, const SiteReputationOptions& options) {
    ThreatReport report;
    report.subject = url;
    const ParsedUrl parsed = parseUrl(url);
    if (!parsed.valid) return report;

    for (const std::string& allowed : options.allowedHosts) {
        if (toLower(allowed) == parsed.host) return report;
    }

    report.identifiedType = parsed.scheme;

    // Opaque schemes used to run content without an origin the user can read.
    if (parsed.scheme == "data" || parsed.scheme == "blob") {
        addFinding(report, {"url.opaque_scheme",
                            "top-level navigation to a " + parsed.scheme +
                                ": URL hides the real origin",
                            ThreatSeverity::Dangerous, 45});
        return report;
    }
    if (parsed.scheme == "javascript") {
        addFinding(report, {"url.javascript_scheme",
                            "javascript: URL entered as a navigation, the "
                            "classic self-XSS delivery",
                            ThreatSeverity::Dangerous, 50});
        return report;
    }
    if (parsed.scheme == "file") {
        addFinding(report, {"url.file_scheme",
                            "page navigates to a local file",
                            ThreatSeverity::Notice, 10});
    }

    // Authority tricks.
    if (!parsed.userInfo.empty()) {
        addFinding(report, {"url.userinfo",
                            "URL carries credentials before the host, which "
                            "hides the real destination: " + parsed.userInfo + "@",
                            ThreatSeverity::Dangerous, 45});
    }
    if (isIpLiteral(parsed.host)) {
        addFinding(report, {"url.ip_literal",
                            "site is addressed by raw IP instead of a name",
                            ThreatSeverity::Suspicious, 25});
    }
    if (parsed.host.rfind("xn--", 0) == 0 ||
        parsed.host.find(".xn--") != std::string::npos) {
        addFinding(report, {"url.punycode",
                            "host uses punycode, so the displayed name may "
                            "not be the real one",
                            ThreatSeverity::Suspicious, 30});
    }
    const size_t labelCount =
        static_cast<size_t>(std::count(parsed.host.begin(), parsed.host.end(), '.')) + 1;
    if (labelCount >= 5) {
        addFinding(report, {"url.deep_subdomains",
                            "host has " + std::to_string(labelCount) +
                                " labels, which is used to push the real "
                                "domain out of view",
                            ThreatSeverity::Suspicious, 20});
    }
    if (inList(tldOf(parsed.host), kHighRiskTlds,
               sizeof(kHighRiskTlds) / sizeof(kHighRiskTlds[0]))) {
        addFinding(report, {"url.high_risk_tld",
                            "top-level domain ." + tldOf(parsed.host) +
                                " is heavily abused for phishing",
                            ThreatSeverity::Notice, 15});
    }
    if (inList(registrableSuffix(parsed.host), kUrlShorteners,
               sizeof(kUrlShorteners) / sizeof(kUrlShorteners[0]))) {
        addFinding(report, {"url.shortener",
                            "link shortener conceals the destination",
                            ThreatSeverity::Notice, 10});
    }

    std::string impersonated;
    if (looksLikeImpersonation(parsed.host, &impersonated)) {
        addFinding(report, {"url.brand_impersonation",
                            "host imitates " + impersonated +
                                " but is not that site",
                            ThreatSeverity::Dangerous, 55});
    }

    // Path and query.
    const std::string lowerPath = toLower(parsed.path);
    static const char* const kCredentialWords[] = {"login", "signin", "verify",
                                                   "account", "secure", "update",
                                                   "wallet", "recover", "unlock"};
    int credentialHits = 0;
    for (const char* word : kCredentialWords)
        if (lowerPath.find(word) != std::string::npos) credentialHits++;
    if (credentialHits >= 2 && !impersonated.empty()) {
        addFinding(report, {"url.credential_path",
                            "path is built from credential-capture words",
                            ThreatSeverity::Dangerous, 35});
    } else if (credentialHits >= 3) {
        addFinding(report, {"url.credential_path",
                            "path stacks several credential-capture words",
                            ThreatSeverity::Suspicious, 20});
    }
    // A second absolute URL inside the query is the open-redirect pattern.
    if (parsed.query.find("http%3a") != std::string::npos ||
        parsed.query.find("http://") != std::string::npos ||
        parsed.query.find("https://") != std::string::npos) {
        addFinding(report, {"url.embedded_url",
                            "query embeds another absolute URL (open redirect)",
                            ThreatSeverity::Notice, 15});
    }
    // Direct link to runnable content.
    const size_t lastSlash = lowerPath.find_last_of('/');
    const std::string leaf = lastSlash == std::string::npos
                                 ? lowerPath
                                 : lowerPath.substr(lastSlash + 1);
    const size_t dot = leaf.find_last_of('.');
    if (dot != std::string::npos && isExecutableExtension(leaf.substr(dot + 1))) {
        addFinding(report, {"url.executable_link",
                            "link points directly at an executable file",
                            ThreatSeverity::Suspicious, 20});
    }

    if (options.flagPlaintext && parsed.scheme == "http") {
        addFinding(report, {"url.plaintext",
                            "connection is plain http, so the page can be "
                            "modified in transit",
                            ThreatSeverity::Suspicious, 25});
    }

    return report;
}

}  // namespace lethe
