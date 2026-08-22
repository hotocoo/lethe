#ifndef LETHE_SECURITY_CSP_POLICY_H
#define LETHE_SECURITY_CSP_POLICY_H

#include <string>
#include <vector>
#include <map>

namespace lethe {

// Content-Security-Policy model for Lethe.
//
// Lethe's reader never executes scripts or loads remote assets, so this
// class exists to DECIDE AND REPORT policy: what the browser would allow,
// and the exact policy string it advertises. Semantics are deliberate:
//   - 'self' only matches when the document origin is supplied; without it
//     'self' matches NOTHING (fail closed).
//   - Scheme/host prefixes ("https:", "https://fonts.gstatic.com") match by
//     prefix, like CSP source expressions.
//   - 'none' denies everything in its directive.
class CSPPolicy {
public:
    CSPPolicy()
        : allowEval(false), allowInlineScripts(false), allowDataURIs(true) {}

    void set_strict_policy() {
        allowEval = false;
        allowInlineScripts = false;
        allowDataURIs = true;
        frameAncestors_ = "'self'";

        directives.clear();
        directives["default-src"] = {"'self'"};
        directives["script-src"] = {"'self'", "https://apis.google.com"};
        directives["style-src"] = {"'self'"};
        directives["img-src"] = {"'self'", "data:", "https:"};
        directives["font-src"] = {"'self'", "https://fonts.gstatic.com"};
        directives["media-src"] = {"'self'"};
        directives["frame-src"] = {"'none'"};
        directives["object-src"] = {"'none'"};
        directives["base-uri"] = {"'self'"};
        directives["form-action"] = {"'self'"};

        policyString_ = buildPolicyString();
    }

    // Whether a script source would be permitted to run.
    // Blocks script-scheme URIs and HTML data: documents outright; rejects
    // inline execution while inline scripts are disallowed. A bare host or
    // CDN path is NEVER judged by accidental substrings of its name.
    bool allowsExecution(const std::string& scriptSrc) const {
        if (hasPrefix(scriptSrc, "javascript:")) return false;
        if (hasPrefix(scriptSrc, "vbscript:")) return false;
        if (hasPrefix(scriptSrc, "data:text/html")) return false;
        if (!allowInlineScripts &&
            scriptSrc.find("'unsafe-inline'") != std::string::npos) {
            return false;
        }
        return true;
    }

    // Resource decision for a directive ("img-src", ...) against the page's
    // origin ("https://example.org"). This is the precise form: 'self'
    // matches URLs under the given origin only.
    bool allowsResource(const std::string& directive, const std::string& url,
                        const std::string& selfOrigin) const {
        const std::vector<std::string>* sources = sourcesFor(directive);
        if (!sources) return false;
        return matchSources(*sources, url, selfOrigin);
    }

    // Origin-less variant kept for callers without document context:
    // 'self' cannot be verified and therefore matches nothing.
    bool allowsResource(const std::string& directive,
                        const std::string& url) const {
        const std::vector<std::string>* sources = sourcesFor(directive);
        if (!sources) return false;
        return matchSources(*sources, url, "");
    }

    // The advertised policy header value, built from the directive map.
    std::string buildPolicyString() const {
        static const char* kOrder[] = {
            "default-src", "script-src", "style-src", "img-src",
            "font-src", "media-src", "frame-src", "object-src",
            "base-uri", "form-action"};
        std::string out;
        for (const char* name : kOrder) {
            const auto it = directives.find(name);
            if (it == directives.end() || it->second.empty()) continue;
            if (!out.empty()) out += "; ";
            out += name;
            for (const auto& src : it->second) {
                out += ' ';
                out += src;
            }
        }
        if (!frameAncestors_.empty()) {
            if (!out.empty()) out += "; ";
            out += "frame-ancestors ";
            out += frameAncestors_;
        }
        return out;
    }

    const std::string& getPolicyString() const { return policyString_; }
    bool allowsEval() const { return allowEval; }
    bool allowsInlineScripts() const { return allowInlineScripts; }
    bool allowsDataUris() const { return allowDataURIs; }

private:
    static bool hasPrefix(const std::string& s, const std::string& prefix) {
        return s.rfind(prefix, 0) == 0;
    }

    const std::vector<std::string>* sourcesFor(
        const std::string& directive) const {
        auto it = directives.find(directive);
        if (it == directives.end()) it = directives.find("default-src");
        return it == directives.end() ? nullptr : &it->second;
    }

    static bool matchSources(const std::vector<std::string>& sources,
                             const std::string& url,
                             const std::string& selfOrigin) {
        for (const auto& src : sources) {
            if (src == "'none'") return false;
            if (src == "*") return true;
            if (src == "'self'") {
                // Origin must match up to a real path/query/fragment
                // boundary: example.org must not accept example.org.evil.io.
                if (!selfOrigin.empty() && hasPrefix(url, selfOrigin)) {
                    const char next = url.size() > selfOrigin.size()
                                          ? url[selfOrigin.size()]
                                          : '\0';
                    if (next == '\0' || next == '/' || next == '?' ||
                        next == '#') {
                        return true;
                    }
                }
                continue; // 'self' unverifiable here: keep looking
            }
            if (hasPrefix(url, src)) return true;
        }
        return false;
    }

    bool allowEval;
    bool allowInlineScripts;
    bool allowDataURIs;
    std::string frameAncestors_;
    std::string policyString_;
    std::map<std::string, std::vector<std::string>> directives;
};

} // namespace lethe

#endif // LETHE_SECURITY_CSP_POLICY_H
