// test_csp_policy.cc — Content-Security-Policy decision semantics

#include "test_framework.h"
#include "security/csp_policy.h"

using namespace lethe;

namespace {
CSPPolicy strict() {
    CSPPolicy p;
    p.set_strict_policy();
    return p;
}
} // namespace

LETHE_TEST_CASE(CSPPolicy_StrictPolicyString) {
    const CSPPolicy p = strict();
    const std::string& s = p.getPolicyString();
    CHECK_TRUE(s.find("default-src 'self'") != std::string::npos);
    CHECK_TRUE(s.find("script-src 'self' https://apis.google.com") !=
               std::string::npos);
    CHECK_TRUE(s.find("frame-src 'none'") != std::string::npos);
    CHECK_TRUE(s.find("frame-ancestors 'self'") != std::string::npos);
    CHECK_FALSE(p.allowsEval());
    CHECK_FALSE(p.allowsInlineScripts());
    CHECK_TRUE(p.allowsDataUris());
}

LETHE_TEST_CASE(CSPPolicy_ExecutionRules) {
    const CSPPolicy p = strict();
    // Script-scheme URIs are always denied.
    CHECK_FALSE(p.allowsExecution("javascript:alert(1)"));
    CHECK_FALSE(p.allowsExecution("vbscript:x"));
    CHECK_FALSE(p.allowsExecution("data:text/html,<script>..."));
    // Inline source markers denied while inline scripts are disallowed.
    CHECK_FALSE(p.allowsExecution("script-src 'self' 'unsafe-inline'"));
    // REGRESSION: a CDN path containing the substring "eval" (retrieval!)
    // must not be blocked by name.
    CHECK_TRUE(p.allowsExecution("https://cdn.example.com/retrieval.js"));
    CHECK_TRUE(p.allowsExecution("https://apis.google.com/js/api.js"));
}

LETHE_TEST_CASE(CSPPolicy_ResourceMatching_WithOrigin) {
    const CSPPolicy p = strict();
    const std::string origin = "https://example.org";

    // 'self' matches only the document's own origin.
    CHECK_TRUE(p.allowsResource("img-src", "https://example.org/i.png",
                                origin));
    CHECK_FALSE(p.allowsResource("img-src", "http://example.org/i.png",
                                 origin)); // scheme matters
    // style-src is 'self'-only: origin must match up to a path boundary,
    // so sibling-host lookalikes (example.org.evil.io) never pass. Note
    // img-src also carries the "https:" wildcard by design, so it allows
    // any HTTPS host - boundary strictness is asserted on style-src here.
    CHECK_TRUE(p.allowsResource("style-src", "https://example.org/app.css",
                                origin));
    CHECK_FALSE(p.allowsResource("style-src", "https://example.org.evil.io/x",
                                 origin));
    CHECK_FALSE(p.allowsResource("style-src", "https://example.orgx/x",
                                 origin));
    // Explicit host prefix.
    CHECK_TRUE(p.allowsResource("script-src", "https://apis.google.com/v1/x",
                                origin));
    CHECK_FALSE(p.allowsResource("script-src", "https://evil.com/x", origin));
    // Scheme wildcard token.
    CHECK_TRUE(p.allowsResource("img-src", "https://anywhere.test/x", origin));
    // 'none' denies everything in its directive.
    CHECK_FALSE(p.allowsResource("frame-src", "https://example.org/f", origin));
    // Unknown directive falls back to default-src 'self'.
    CHECK_TRUE(p.allowsResource("worker-src", "https://example.org/w", origin));
    CHECK_FALSE(p.allowsResource("worker-src", "https://other.test/w", origin));
}

LETHE_TEST_CASE(CSPPolicy_Originless_SelfFailsClosed) {
    const CSPPolicy p = strict();
    // Without an origin, 'self' can never be verified: it matches NOTHING.
    // (script-src holds no scheme wildcard, so only 'self' could allow it.)
    CHECK_FALSE(p.allowsResource("script-src", "https://example.org/i.png"));
    // But explicit scheme/host tokens still work.
    CHECK_TRUE(p.allowsResource("script-src", "https://apis.google.com/x"));
    CHECK_TRUE(p.allowsResource("img-src", "https://anything.test/x"));
    CHECK_FALSE(p.allowsResource("script-src", "https://evil.com/x"));
}

LETHE_TEST_CASE(CSPPolicy_EmptyPolicyDeniesByDefault) {
    CSPPolicy p; // never configured: no directives at all
    CHECK_TRUE(p.getPolicyString().empty());
    CHECK_FALSE(p.allowsResource("img-src", "https://example.org/x",
                                 "https://example.org"));
    CHECK_FALSE(p.allowsResource("anything", "https://example.org/x"));
    CHECK_TRUE(p.allowsExecution("https://cdn.example.com/app.js"));
}
