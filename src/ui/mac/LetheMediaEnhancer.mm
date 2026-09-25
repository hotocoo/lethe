#import "ui/mac/LetheMediaEnhancer.h"
#import "ui/mac/LethePreferences.h"

#include <cstdlib>
#include <string>

namespace {
const char kMediaEnhancerJS[] =
#include "renderer/media_enhancer.js.inc"
    ;

std::string LowerEnv(const char* name) {
    const char* v = getenv(name);
    std::string s = v ? v : "";
    for (char& ch : s) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    return s;
}
}  // namespace

NSInteger LetheMediaEnhancerMode(void) {
    const std::string v = LowerEnv("LETHE_UPSCALER");
    if (!v.empty() && !getenv("LETHE_UPSCALER_FROM_PREFS")) {
        if (v == "linear") return 1;
        if (v == "metalfx-sharp" || v == "fsr-sharp") return 3;
        if (v == "metalfx" || v == "metalfx-spatial" || v == "fsr") return 2;
        return 0;
    }
    switch ([LethePreferences shared].upscaler) {
        case LetheUpscalerLinear: return 1;
        case LetheUpscalerFSR1: return 2;
        case LetheUpscalerDLSSLike: return 3;
        default: return 0;
    }
}

BOOL LetheMediaEnhancerHDR(void) {
    const std::string v = LowerEnv("LETHE_HDR_ENHANCE");
    if (!v.empty()) return v == "1" || v == "on" || v == "true";
    return [LethePreferences shared].hdrEnhance;
}

NSString* LetheMediaUpscalerScript(void) {
    NSString* js = [NSString stringWithUTF8String:kMediaEnhancerJS];
    js = [js stringByReplacingOccurrencesOfString:@"__LETHE_INITIAL_MODE__"
              withString:[NSString stringWithFormat:@"%ld", (long)LetheMediaEnhancerMode()]];
    return [js stringByReplacingOccurrencesOfString:@"__LETHE_INITIAL_HDR__"
              withString:LetheMediaEnhancerHDR() ? @"1" : @"0"];
}

NSString* LetheMediaEnhancerApplyJS(void) {
    return [NSString stringWithFormat:
        @"window.__letheMediaUpscalerSetMode && window.__letheMediaUpscalerSetMode(%ld,%d);",
        (long)LetheMediaEnhancerMode(), LetheMediaEnhancerHDR() ? 1 : 0];
}
