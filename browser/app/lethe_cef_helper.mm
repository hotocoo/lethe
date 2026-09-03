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
#include "include/cef_sandbox_mac.h"
#include "include/wrapper/cef_library_loader.h"

#include "app/cef_render_handler.h"

// The helper process hosts the renderer (and GPU / network / utility).
// The renderer needs the LetheCefRenderHandler so it can answer the
// browser process's "lethe:eval" messages (the e2e + bench eval path).
// Without it the renderer never replies and print-js times out.
class LetheHelperApp : public CefApp {
 public:
    CefRefPtr<CefRenderProcessHandler> GetRenderProcessHandler() override {
        if (!render_process_handler_) {
            render_process_handler_ = new LetheCefRenderHandler();
        }
        return render_process_handler_;
    }
 private:
    CefRefPtr<CefRenderProcessHandler> render_process_handler_;
    IMPLEMENT_REFCOUNTING(LetheHelperApp);
};

int main(int argc, char* argv[]) {
    // CEF's macOS sandbox must be initialized before the helper loads the
    // framework. The official CEF helper sequence is sandbox -> dynamic CEF
    // library load -> CefExecuteProcess. This preserves renderer/GPU
    // process isolation instead of relying solely on Lethe's outer Seatbelt.
    CefScopedSandboxContext sandbox_context;
    if (!sandbox_context.Initialize(argc, argv)) {
        std::cerr << "[lethe-cef-helper] CEF sandbox initialization failed" << std::endl;
        return 1;
    }
    CefScopedLibraryLoader library_loader;
    if (!library_loader.LoadInHelper()) {
        std::cerr << "[lethe-cef-helper] CEF framework load failed" << std::endl;
        return 1;
    }

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
