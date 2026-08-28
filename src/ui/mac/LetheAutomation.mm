// LetheAutomation.mm - scripted end-to-end driver for the macOS shell
//
// One command per line ('#' comments). Every command completes (or fails)
// before the next runs; assertions that fail stop the run. Process exit
// status: 0 when every assertion held, 1 otherwise. Used to dogfood the
// browser like a user would - without Accessibility permissions.
//
//   load <text>               address-bar semantics (URL or search)
//   wait [ms]                 until the tab finished loading (default 20000)
//   try-wait [ms]             same, but a timeout is logged and NOT fatal
//   sleep <ms>
//   newtab [text]             new tab beside the current one; becomes current
//   oblivion [text]           new Oblivion window (isolated, https-only); current
//   assert-oblivion on|off    current tab is (not) an Oblivion tab
//   closetab                  close current tab
//   back | forward | reload | reader
//   click <css-selector>      DOM click via JavaScript
//   type-address <text>       type into the address bar and press Enter
//   js <code>                 evaluate; result kept for assert-last
//   wait-js <ms> <code>       poll until <code> is truthy (or fail after ms)
//   print-js <code>           evaluate and echo "[e2e] result <text>"
//   mark <text>               echo "[e2e] mark <text>" (harness sync point)
//   screenshot <path.png>
//   assert-url-contains <s>   | assert-title-contains <s>
//   assert-body-contains <s>  | assert-tabs <n> | assert-reader <on|off>
//   assert-js <code>          JavaScript must evaluate truthy
//   quit

#import "ui/mac/LetheShell.h"

#include <cstdlib>
#include <iostream>

@interface LetheAutomation () {
    __weak LetheAppDelegate* app_;
    NSArray<NSString*>* lines_;
    NSUInteger index_;
    BrowserWindowController* current_;
    int failures_;
    NSString* lastJs_;
    dispatch_source_t keepFrontTimer_;
}
@end

@implementation LetheAutomation

- (instancetype)initWithDelegate:(LetheAppDelegate*)app scriptPath:(NSString*)path {
    if ((self = [super init])) {
        app_ = app;
        NSError* err = nil;
        NSString* text = [NSString stringWithContentsOfFile:path
                                                  encoding:NSUTF8StringEncoding error:&err];
        if (!text) {
            std::cerr << "[e2e] cannot read script " << path.UTF8String << std::endl;
            text = @"";
            failures_ = 1;
        }
        lines_ = [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        index_ = 0;
    }
    return self;
}

// Keep the browser frontmost while a script runs. WebKit suspends
// requestAnimationFrame (and reports document.visibilityState "hidden")
// for occluded windows, which hangs animation-driven benchmarks such as
// MotionMark; a window launched from the command line does not reliably
// win activation on its own, so we re-assert it. Only when another app is
// in front, so an interactive user looking at Lethe is never fought.
- (void)keepFront {
    // Best-effort bring-forward for animation benchmarks (MotionMark).
    // A CLI-launched Lethe does not reliably win activation on its own,
    // and WebKit stops firing rAF when the WKWebView's window is
    // occluded. We try the modern LaunchServices path AND the direct
    // AppKit calls; whichever succeeds, the window goes frontmost.
    // No repeating timer: that stole focus from the address bar every
    // 2 s and made interactive use unusable.
    [[NSRunningApplication currentApplication]
        activateWithOptions:NSApplicationActivateIgnoringOtherApps];
    [NSApp activateIgnoringOtherApps:YES];
    BrowserWindowController* c = (current_ && current_.window) ? current_ : app_.controllers.lastObject;
    if (c && c.window) {
        [c.window orderFrontRegardless];
        [c.window makeKeyAndOrderFront:nil];
    }
}

- (void)start {
    current_ = app_.controllers.firstObject;
    std::cout << "[e2e] start: " << lines_.count << " lines" << std::endl;
    // Re-assert frontmost every 2 s for the life of the script, but only
    // when asked: animation benchmarks (MotionMark) need it, and it must
    // not steal focus from an interactive user during ordinary runs.
    const char* keepFront = getenv("LETHE_KEEP_FRONT");
    if (keepFront && keepFront[0] && keepFront[0] != '0') {
        // Repeating bring-forward (the original approach).
        // Fires once at t=0 before ARC releases the local; the first
        // makeKeyAndOrderFront is what un-sticks WKWebView.
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,
                                                          0, 0, dispatch_get_main_queue());
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 0),
                                  2 * NSEC_PER_SEC, 200 * NSEC_PER_MSEC);
        __weak LetheAutomation* weakSelf = self;
        dispatch_source_set_event_handler(timer, ^{ [weakSelf keepFront]; });
        dispatch_resume(timer);
        std::cout << "[e2e] keep-front: on" << std::endl;
    }
    if (keepFront && keepFront[0] && keepFront[0] != '0') {
        keepFrontTimer_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,
                                                          0, 0, dispatch_get_main_queue());
        dispatch_source_set_timer(keepFrontTimer_, dispatch_time(DISPATCH_TIME_NOW, 0),
                                  2 * NSEC_PER_SEC, 200 * NSEC_PER_MSEC);
        __strong LetheAutomation* strongSelf = self;
        dispatch_source_set_event_handler(keepFrontTimer_, ^{ [strongSelf keepFront]; });
        dispatch_resume(keepFrontTimer_);
        std::cout << "[e2e] keep-front: on" << std::endl;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{ [self next]; });
}

- (void)finishWithMessage:(const char*)msg {
    std::cout << "[e2e] " << msg << (failures_ ? " (FAILED)" : " (PASSED)") << std::endl;
    std::cout.flush();
    lethe::ShellContext* ctx = app_.context;
    if (ctx && ctx->onTerminate) ctx->onTerminate();
    std::exit(failures_ ? 1 : 0);
}

- (void)fail:(NSString*)what {
    failures_++;
    std::cout << "[e2e] FAIL line " << index_ << ": " << what.UTF8String << std::endl;
    // Evidence for the report: the current tab as the user would see it.
    NSWindow* w = current_.window;
    if (w) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CGImageRef img = CGWindowListCreateImage(CGRectNull, kCGWindowListOptionIncludingWindow,
                                                 (CGWindowID)w.windowNumber,
                                                 kCGWindowImageBoundsIgnoreFraming);
#pragma clang diagnostic pop
        if (img) {
            NSBitmapImageRep* rep = [[NSBitmapImageRep alloc] initWithCGImage:img];
            CGImageRelease(img);
            NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"lethe-e2e-failure.png"];
            [[rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}]
                writeToFile:path atomically:YES];
            std::cout << "[e2e] failure screenshot: " << path.UTF8String << std::endl;
        }
    }
    [self finishWithMessage:"stopped on first failure"];
}

- (void)pass:(NSString*)what {
    std::cout << "[e2e] ok   " << what.UTF8String << std::endl;
}

- (void)next {
    // Refresh current tab like a user's eyes would: the key window when the
    // app is active; otherwise the selected tab of the current window's tab
    // group (another app - e.g. a benchmark's Chrome - holding focus must
    // not change what the script sees).
    NSWindowController* keyWc = [NSApp keyWindow].windowController;
    if ([keyWc isKindOfClass:[BrowserWindowController class]] &&
        [app_.controllers containsObject:(BrowserWindowController*)keyWc]) {
        current_ = (BrowserWindowController*)keyWc;
    } else if ([app_.controllers containsObject:current_]) {
        NSWindowController* selWc = current_.window.tabGroup.selectedWindow.windowController;
        if ([selWc isKindOfClass:[BrowserWindowController class]] &&
            [app_.controllers containsObject:(BrowserWindowController*)selWc]) {
            current_ = (BrowserWindowController*)selWc;
        }
    } else {
        current_ = app_.controllers.lastObject;
    }
    while (index_ < lines_.count) {
        NSString* raw = lines_[index_++];
        NSString* line = [raw stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
        if (!line.length || [line hasPrefix:@"#"]) continue;
        [self run:line];
        return;
    }
    [self finishWithMessage:"script complete"];
}

- (void)later:(double)ms {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(ms * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{ [self next]; });
}

- (void)waitForLoadWithTimeout:(double)ms started:(NSDate*)started minimum:(double)minMs {
    const double elapsed = -[started timeIntervalSinceNow] * 1000.0;
    WKWebView* web = current_.webView;
    if (!web) { [self fail:@"no current tab"]; return; }
    if (elapsed >= minMs && !current_.busy) {
        // Settle: let title/URL KVO land.
        [self later:250];
        return;
    }
    if (elapsed > ms) { [self fail:[NSString stringWithFormat:@"wait: still loading after %.0f ms", ms]]; return; }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        [self waitForLoadWithTimeout:ms started:started minimum:minMs];
    });
}

- (void)softWaitWithTimeout:(double)ms started:(NSDate*)started {
    const double elapsed = -[started timeIntervalSinceNow] * 1000.0;
    if (elapsed >= 300 && !current_.busy) { [self later:250]; return; }
    if (elapsed > ms) {
        std::cout << "[e2e] timeout try-wait: still loading after " << (int)ms << " ms" << std::endl;
        std::cout.flush();
        [current_ stopLoading:nil];
        [self later:250];
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        [self softWaitWithTimeout:ms started:started];
    });
}

- (void)evaluate:(NSString*)code completion:(void (^)(id result, NSError* err))completion {
    [current_.webView evaluateJavaScript:code completionHandler:^(id result, NSError* err) {
        completion(result, err);
    }];
}

- (void)run:(NSString*)line {
    NSRange sp = [line rangeOfString:@" "];
    NSString* cmd = sp.location == NSNotFound ? line : [line substringToIndex:sp.location];
    NSString* arg = sp.location == NSNotFound ? @"" :
        [[line substringFromIndex:sp.location + 1]
            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    std::cout << "[e2e] > " << line.UTF8String << std::endl;

    if (!current_ && ![cmd isEqualToString:@"newtab"] && ![cmd isEqualToString:@"quit"] &&
        ![cmd isEqualToString:@"assert-tabs"]) {
        [self fail:@"no browser tab available"];
        return;
    }

    if ([cmd isEqualToString:@"load"]) {
        [current_ loadAddress:arg];
        [self later:50];
    } else if ([cmd isEqualToString:@"type-address"]) {
        [current_ focusAddressBar:nil];
        current_.addressField.stringValue = arg;
        [current_ addressEntered:nil];
        [self later:50];
    } else if ([cmd isEqualToString:@"wait"]) {
        const double ms = arg.length ? arg.doubleValue : 20000;
        [self waitForLoadWithTimeout:ms started:[NSDate date] minimum:300];
    } else if ([cmd isEqualToString:@"try-wait"]) {
        // Like wait, but a timeout is reported ("[e2e] timeout ...") and the
        // script continues: benchmarks record it as a data point.
        const double ms = arg.length ? arg.doubleValue : 20000;
        [self softWaitWithTimeout:ms started:[NSDate date]];
    } else if ([cmd isEqualToString:@"sleep"]) {
        [self later:MAX(0, arg.doubleValue)];
    } else if ([cmd isEqualToString:@"newtab"]) {
        BrowserWindowController* c =
            [app_ openTabWithURL:arg.length ? arg : nil fromWindow:current_.window webView:nil];
        current_ = c;
        [self later:100];
    } else if ([cmd isEqualToString:@"oblivion"]) {
        // oblivion [url]: open an Oblivion window; it becomes current.
        BrowserWindowController* c = [app_ openOblivionWindowWithURL:arg.length ? arg : nil];
        current_ = c;
        [self later:150];
    } else if ([cmd isEqualToString:@"assert-oblivion"]) {
        const BOOL want = [arg isEqualToString:@"on"];
        if (current_.oblivion == want) { [self pass:@"oblivion state"]; [self next]; }
        else [self fail:[NSString stringWithFormat:@"oblivion %@", current_.oblivion ? @"on" : @"off"]];
    } else if ([cmd isEqualToString:@"closetab"]) {
        [current_.window performClose:nil];
        current_ = nil;
        [self later:200];
    } else if ([cmd isEqualToString:@"back"]) {
        [current_ goBack:nil]; [self later:50];
    } else if ([cmd isEqualToString:@"forward"]) {
        [current_ goForward:nil]; [self later:50];
    } else if ([cmd isEqualToString:@"reload"]) {
        [current_ reloadPage:nil]; [self later:50];
    } else if ([cmd isEqualToString:@"reader"]) {
        [current_ toggleReader:nil]; [self later:50];
    } else if ([cmd isEqualToString:@"click"]) {
        NSString* js = [NSString stringWithFormat:
            @"(function(){var e=document.querySelector(%@);if(!e)return 'missing';e.click();return 'clicked';})()",
            [self jsString:arg]];
        [self evaluate:js completion:^(id result, NSError* err) {
            if (err || ![result isEqual:@"clicked"]) {
                [self fail:[NSString stringWithFormat:@"click %@: %@", arg,
                            err ? err.localizedDescription : result]];
                return;
            }
            [self later:50];
        }];
    } else if ([cmd isEqualToString:@"js"]) {
        [self evaluate:arg completion:^(id result, NSError* err) {
            if (err) { [self fail:[NSString stringWithFormat:@"js: %@", err.localizedDescription]]; return; }
            self->lastJs_ = [NSString stringWithFormat:@"%@", result];
            [self next];
        }];
    } else if ([cmd isEqualToString:@"wait-js"]) {
        // wait-js <timeout-ms> <code>: poll until the expression is truthy.
        NSRange sp2 = [arg rangeOfString:@" "];
        if (sp2.location == NSNotFound) { [self fail:@"wait-js needs <timeout-ms> <code>"]; return; }
        const double ms = [arg substringToIndex:sp2.location].doubleValue;
        NSString* code = [[arg substringFromIndex:sp2.location + 1]
            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        [self pollJs:code deadline:[NSDate dateWithTimeIntervalSinceNow:ms / 1000.0] timeoutMs:ms];
    } else if ([cmd isEqualToString:@"print-js"]) {
        // print-js <code>: evaluate and echo the result on stdout as
        // "[e2e] result <text>" for external harnesses (tools/bench).
        [self evaluate:arg completion:^(id result, NSError* err) {
            if (err) { [self fail:[NSString stringWithFormat:@"print-js: %@", err.localizedDescription]]; return; }
            NSString* text = [self stringify:result];
            self->lastJs_ = text;
            std::cout << "[e2e] result " << text.UTF8String << std::endl;
            std::cout.flush();
            [self next];
        }];
    } else if ([cmd isEqualToString:@"mark"]) {
        // mark <text>: synchronisation point for external harnesses.
        std::cout << "[e2e] mark " << arg.UTF8String << std::endl;
        std::cout.flush();
        [self next];
    } else if ([cmd isEqualToString:@"screenshot"]) {
        [self screenshotTo:arg];
    } else if ([cmd isEqualToString:@"assert-url-contains"]) {
        NSString* url = current_.webView.URL.absoluteString ?: @"";
        NSString* shown = current_.addressField.stringValue ?: @"";
        if ([url containsString:arg] || [shown containsString:arg]) {
            [self pass:[NSString stringWithFormat:@"url %@", url]]; [self next];
        } else {
            [self fail:[NSString stringWithFormat:@"url '%@' (shown '%@') lacks '%@'", url, shown, arg]];
        }
    } else if ([cmd isEqualToString:@"assert-title-contains"]) {
        NSString* t = current_.window.title ?: @"";
        if ([t.lowercaseString containsString:arg.lowercaseString]) {
            [self pass:[NSString stringWithFormat:@"title '%@'", t]]; [self next];
        } else {
            [self fail:[NSString stringWithFormat:@"title '%@' lacks '%@'", t, arg]];
        }
    } else if ([cmd isEqualToString:@"assert-body-contains"]) {
        [self evaluate:@"document.body ? document.body.innerText : ''" completion:^(id result, NSError* err) {
            NSString* body = [result isKindOfClass:[NSString class]] ? result : @"";
            if (!err && [body containsString:arg]) {
                [self pass:[NSString stringWithFormat:@"body contains '%@'", arg]]; [self next];
            } else {
                [self fail:[NSString stringWithFormat:@"body lacks '%@' (%@)", arg,
                            err ? err.localizedDescription : [body substringToIndex:MIN(body.length, 200u)]]];
            }
        }];
    } else if ([cmd isEqualToString:@"assert-tabs"]) {
        NSUInteger n = current_ ? (current_.window.tabGroup.windows.count ?: 1) : 0;
        if (!current_) n = app_.controllers.count;
        if ((NSInteger)n == arg.integerValue) {
            [self pass:[NSString stringWithFormat:@"%lu tabs", (unsigned long)n]]; [self next];
        } else {
            [self fail:[NSString stringWithFormat:@"tabs=%lu expected %@", (unsigned long)n, arg]];
        }
    } else if ([cmd isEqualToString:@"assert-reader"]) {
        const BOOL want = [arg isEqualToString:@"on"];
        if (current_.readerActive == want) { [self pass:@"reader state"]; [self next]; }
        else [self fail:[NSString stringWithFormat:@"reader %@", current_.readerActive ? @"on" : @"off"]];
    } else if ([cmd isEqualToString:@"assert-js"]) {
        [self evaluate:arg completion:^(id result, NSError* err) {
            const BOOL truthy = result && ![result isEqual:@NO] && ![result isEqual:@0] &&
                                ![result isEqual:@""] && ![result isKindOfClass:[NSNull class]];
            if (!err && truthy) { [self pass:[NSString stringWithFormat:@"js -> %@", result]]; [self next]; }
            else [self fail:[NSString stringWithFormat:@"assert-js '%@' -> %@", arg,
                             err ? err.localizedDescription : result]];
        }];
    } else if ([cmd isEqualToString:@"quit"]) {
        [self finishWithMessage:"quit"];
    } else {
        [self fail:[NSString stringWithFormat:@"unknown command '%@'", cmd]];
    }
}

- (NSString*)stringify:(id)result {
    if (!result || [result isKindOfClass:[NSNull class]]) return @"null";
    if ([result isKindOfClass:[NSString class]]) return result;
    if ([result isKindOfClass:[NSNumber class]]) return [result stringValue];
    if ([NSJSONSerialization isValidJSONObject:result]) {
        NSData* d = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
        if (d) return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @"";
    }
    return [NSString stringWithFormat:@"%@", result];
}

- (void)pollJs:(NSString*)code deadline:(NSDate*)deadline timeoutMs:(double)ms {
    [self evaluate:code completion:^(id result, NSError* err) {
        const BOOL truthy = !err && result && ![result isEqual:@NO] && ![result isEqual:@0] &&
                            ![result isEqual:@""] && ![result isKindOfClass:[NSNull class]];
        if (truthy) {
            self->lastJs_ = [self stringify:result];
            [self pass:[NSString stringWithFormat:@"wait-js -> %@", self->lastJs_]];
            [self next];
            return;
        }
        if ([deadline timeIntervalSinceNow] <= 0) {
            [self fail:[NSString stringWithFormat:@"wait-js '%@' still falsy after %.0f ms (%@)", code, ms,
                        err ? err.localizedDescription : [self stringify:result]]];
            return;
        }
        // 500 ms: the same cadence the benchmark harness uses to poll Chrome
        // over CDP, so neither browser pays more evaluate() overhead than the other.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            [self pollJs:code deadline:deadline timeoutMs:ms];
        });
    }];
}

- (NSString*)jsString:(NSString*)s {
    NSData* d = [NSJSONSerialization dataWithJSONObject:@[s] options:0 error:nil];
    NSString* arr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    // ["..."] -> "..."
    return [arr substringWithRange:NSMakeRange(1, arr.length - 2)];
}

- (void)screenshotTo:(NSString*)pathIn {
    NSString* path = pathIn;
    if ([path hasPrefix:@"$TMPDIR/"]) {
        path = [NSTemporaryDirectory() stringByAppendingPathComponent:[path substringFromIndex:8]];
    }
    NSWindow* w = current_.window;
    if (!w) { [self fail:@"screenshot: no window"]; return; }
    [w makeKeyAndOrderFront:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CGImageRef img = CGWindowListCreateImage(CGRectNull, kCGWindowListOptionIncludingWindow,
                                                 (CGWindowID)w.windowNumber,
                                                 kCGWindowImageBoundsIgnoreFraming);
#pragma clang diagnostic pop
        if (!img) { [self fail:@"screenshot: capture failed"]; return; }
        NSBitmapImageRep* rep = [[NSBitmapImageRep alloc] initWithCGImage:img];
        CGImageRelease(img);
        NSData* png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        NSError* err = nil;
        if (![png writeToFile:path options:NSDataWritingAtomic error:&err]) {
            [self fail:[NSString stringWithFormat:@"screenshot: %@", err.localizedDescription]];
            return;
        }
        [self pass:[NSString stringWithFormat:@"screenshot %@ (%lux%lu)", path,
                    (unsigned long)rep.pixelsWide, (unsigned long)rep.pixelsHigh]];
        [self next];
    });
}

@end
