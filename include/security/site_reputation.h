// site_reputation.h - local, privacy-preserving risk assessment for URLs
//
// Chrome and Safari answer "is this page dangerous?" by consulting a remote
// service. Lethe cannot: sending every host a user visits to a third party
// is the exact behaviour the rest of this browser exists to prevent. So the
// check is local and structural. It scores the things a phishing or
// malware-delivery URL has to do in order to work:
//
//   - impersonate a known brand (homograph, punycode, typo-distance,
//     brand-in-subdomain, brand-in-path-on-unrelated-host)
//   - hide the real destination (IP literal, userinfo in the authority,
//     deeply nested subdomains, embedded second URL, shortener)
//   - carry credentials or a payload (login/verify paths, executable
//     download link, data: or blob: top-level navigation)
//
// None of these is proof. Each is a cost the attacker pays, and together
// they discriminate well enough to warn on. The verdict always carries its
// evidence so the user can disagree with it.

#ifndef LETHE_SECURITY_SITE_REPUTATION_H
#define LETHE_SECURITY_SITE_REPUTATION_H

#include <string>
#include <vector>

#include "security/threat_report.h"

namespace lethe {

struct SiteReputationOptions {
    // Hosts the user has explicitly trusted; they short-circuit to clean.
    std::vector<std::string> allowedHosts;
    // Treat plain-http top-level navigation as a finding. Lethe is
    // HTTPS-first, so by the time this runs the upgrade already failed.
    bool flagPlaintext = true;
};

// Scores \p url. Never performs network or disk I/O.
ThreatReport assessUrl(const std::string& url,
                       const SiteReputationOptions& options = {});

// True when \p host is confusable with a well-known brand host it is not.
// Exposed for tests and for the warning page's explanation text.
bool looksLikeImpersonation(const std::string& host, std::string* impersonated);

// Levenshtein distance, capped at \p limit for early exit.
size_t editDistance(const std::string& a, const std::string& b, size_t limit);

}  // namespace lethe

#endif  // LETHE_SECURITY_SITE_REPUTATION_H
