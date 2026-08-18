#ifndef LETHE_SECURITY_CSP_POLICY_H
#define LETHE_SECURITY_CSP_POLICY_H

#include <string>
#include <vector>
#include <map>

namespace lethe {

class CSPPolicy {
public:
    CSPPolicy() : allowEval(false), allowInlineScripts(false), allowDataURIs(false) {}
    
    void set_strict_policy() {
        policyString_ = DEFAULT_CSP_POLICY;
        allowEval = false;
        allowInlineScripts = false;
        allowDataURIs = true;
        frameAncestors_ = "'self'";
        
        // Initialize directive map
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
    }
    
    bool allowsExecution(const std::string& scriptSrc) const {
        if (scriptSrc.find("javascript:") != std::string::npos) return false;
        if (scriptSrc.find("eval") != std::string::npos) return false;
        if (!allowInlineScripts && scriptSrc.find("'unsafe-inline'") != std::string::npos) {
            return false;
        }
        return true;
    }
    
    bool allowsResource(const std::string& directive, const std::string& url) const {
        auto it = directives.find(directive);
        if (it == directives.end()) {
            it = directives.find("default-src");
        }
        if (it == directives.end()) return false;
        
        for (const auto& src : it->second) {
            if (src == "*" || src == "'self'" || url.find(src) == 0) {
                return true;
            }
        }
        return false;
    }
    
    const std::string& getPolicyString() const { return policyString_; }
    
private:
    bool allowEval;
    bool allowInlineScripts;
    bool allowDataURIs;
    std::string frameAncestors_;
    std::string policyString_;
    std::map<std::string, std::vector<std::string>> directives;
};

} // namespace lethe

#endif // LETHE_SECURITY_CSP_POLICY_H