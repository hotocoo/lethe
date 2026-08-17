
#ifndef LETHE_SECURITY_CSP_POLICY_H
#define LETHE_SECURITY_CSP_POLICY_H

#include <string>

namespace lethe {

class CSPPolicy {
public:
    void set_strict_policy() {
        policyString_ = DEFAULT_CSP_POLICY;
        allowEval = false;
        allowInlineScripts = false;
        allowDataURIs = true;
        frameAncestors_ = "'self'";
    }

    bool allowsExecution(const std::string& scriptSrc) const {
        if (scriptSrc.find("javascript:") != std::string::npos ||
            scriptSrc.find("eval") != std::string::npos ||
            scriptSrc.find("(self)") != std::string::npos) {
            return false;
        }
        if (!allowInlineScripts && 
            scriptSrc.find("'unsafe-inline'") != std::string::npos) {
            return false;
        }
        return true;
    }

private:
    bool allowEval;
    bool allowInlineScripts;
    bool allowDataURIs;
    std::string frameAncestors_;
    std::string policyString_;
};

} // namespace lethe

#endif
