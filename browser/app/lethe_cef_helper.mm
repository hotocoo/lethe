// lethe_cef_helper.mm - the CEF Helper process binary.
//
// Chromium's multi-process model launches one Helper per renderer / GPU /
// network / utility process. On macOS each Helper is a small .app bundle
// (Contents/MacOS/<helper>) that calls CefExecuteProcess. The browser
// process discovers the helper by looking in the .app's main bundle and
// adjacent Frameworks/, hence the bundled Helper.app layout. We point
// CefSettings.browser_subprocess_path at this binary by relative path.
//
// Built as both a console executable (so it can be debugged) and an .app
// bundle under Frameworks/Lethe CEF Helper.app inside the main bundle.

#include <cstdlib>
#include <iostream>

#include "include/cef_app.h"
#include "include/cef_base.h"

// Minimal CefApp: the helper does no custom work, it just hands off to
// CefExecuteProcess which dispatches to the right sub-process entry point.
class LetheHelperApp : public CefApp {
 private:
    IMPLEMENT_REFCOUNTING(LetheHelperApp);
};

int main(int argc, char* argv[]) {
    // CefExecuteProcess returns -1 in the browser process (we never get
    // here in that case - the browser binary runs the real shell). In a
    // recognised helper (renderer / GPU / network / utility) it blocks
    // until the helper should exit and returns the process exit code.
    CefMainArgs args(argc, argv);
    CefRefPtr<CefApp> app = new LetheHelperApp();
    int rc = CefExecuteProcess(args, app, nullptr);
    if (rc < 0) {
        // Browser process. We should never run from there as a helper,
        // but exit cleanly so the parent doesn't get a SIGKILL signal.
        return 0;
    }
    return rc;
}
