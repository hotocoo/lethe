#ifndef LETHE_SECURITY_CSP_H
#define LETHE_SECURITY_CSP_H

#include <string>

namespace lethe {

class CSPPolicy {
public:
    CSPPolicy();
    
    // Set strict default policy
    void setDefaultPolicy();
    
    // Apply custom policy string
    void setPolicy(const std::string& custom);
    
    // Check if execution is allowed for source
    bool allowsExecution(std::string_view scriptSrc) const;
    
    // Policy flags (for quick checks without parsing)
    bool allowEval;
    bool allowInlineScript;
    bool allowInlineStyle;
    bool allowDataURI;
    
    std::string frameAncestors;
    std::string policyString;
};

} // namespace lethe

#endif // LETHE_SECURITY_CSP_H
