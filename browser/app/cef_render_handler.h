// cef_render_handler.h - CEF render-process handler that lets the
// browser process evaluate arbitrary JavaScript and get the stringified
// result back through a CefProcessMessage. The browser process sends
// "lethe:eval" with the JS code; the renderer evaluates it, stringifies
// the value, and posts back "lethe:eval-result".
#ifndef LETHE_BROWSER_APP_CEF_RENDER_HANDLER_H
#define LETHE_BROWSER_APP_CEF_RENDER_HANDLER_H

#include "include/cef_app.h"
#include "include/cef_render_process_handler.h"

class LetheCefRenderHandler : public CefRenderProcessHandler {
 public:
    LetheCefRenderHandler() = default;
    void OnContextCreated(CefRefPtr<CefBrowser> browser,
                          CefRefPtr<CefFrame> frame,
                          CefRefPtr<CefV8Context> context) override;
    void OnContextReleased(CefRefPtr<CefBrowser> browser,
                           CefRefPtr<CefFrame> frame,
                           CefRefPtr<CefV8Context> context) override;
    bool OnProcessMessageReceived(CefRefPtr<CefBrowser> browser,
                                  CefRefPtr<CefFrame> frame,
                                  CefProcessId source_process,
                                  CefRefPtr<CefProcessMessage> message) override;

 private:
    IMPLEMENT_REFCOUNTING(LetheCefRenderHandler);
};

#endif  // LETHE_BROWSER_APP_CEF_RENDER_HANDLER_H
