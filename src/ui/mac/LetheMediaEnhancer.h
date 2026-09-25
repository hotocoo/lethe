// Page-level media enhancer shared by the WebKit and CEF shells: FSR1
// (EASU + RCAS) spatial upscaling and an SDR HDR-look enhancer, injected at
// document start. Source: src/renderer/media_enhancer.js.inc.
#import <Foundation/Foundation.h>

// 0 off, 1 linear, 2 FSR1, 3 FSR1 + full sharpening. LETHE_UPSCALER
// (none|linear|fsr|metalfx|metalfx-sharp) overrides Settings.
NSInteger LetheMediaEnhancerMode(void);
// LETHE_HDR_ENHANCE=0|1 overrides Settings.
BOOL LetheMediaEnhancerHDR(void);
// Document-start script with the current mode baked in.
NSString* LetheMediaUpscalerScript(void);
// Live re-apply for already-open documents.
NSString* LetheMediaEnhancerApplyJS(void);
