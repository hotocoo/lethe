// csp.cc — Content Security Policy enforcement
#include <string_view>
#include "security/csp.h"

namespace lethe {

const char* const DefaultCSP = 
    "default-src 'self'; "
    "script-src 'self' https://apis.google.com; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self' https://fonts.gstatic.com; "
    "media-src 'self'; "
    "frame-src 'none'; "
    "object-src 'none'; "
    "plugin-types 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "script-src-elem 'strict-dynamic'; "
    "require-trusted-types-for ['default']";

CSPPolicy::CSPPolicy() {
    setDefaultPolicy();
}

void CSPPolicy::setDefaultPolicy() {
    // Disable eval entirely, no inline scripts/styles, strict origins
    allowEval = false;
    allowInlineScript = false;
    allowInlineStyle = false;
    allowDataURI = true;  // Images only via img-src directive
    frameAncestors = "'self'";
    
    // Strict CSP template with nonce support
    policyString = DefaultCSP;
}

void CSPPolicy::setPolicy(const std::string& custom) {
    if (!custom.empty()) {
        policyString = custom;
    } else {
        setDefaultPolicy();
    }
}

bool CSPPolicy::allowsExecution(std::string_view scriptSrc) const {
    // Reject eval-like sources
    if (scriptSrc.find("javascript:") != std::string::npos ||
        scriptSrc.find("eval") != std::string::npos ||
        scriptSrc.find("(self)") != std::string::npos) {
        return false;
    }

    // Enforce no inline scripts unless explicitly allowed
    if (!allowInlineScript && (scriptSrc.find("'unsafe-inline'") != std::string::npos)) {
        return false;
    }

    return true;
}

} // namespace lethe
