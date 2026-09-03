// cef_automation.h - scripted end-to-end driver for the CEF shell.
//
// Same command language as LetheAutomation.mm in the WebKit shell so the
// bench harness can drive both binaries through the same step list. Uses
// the CefBrowser main frame to issue load / eval / poll commands; the
// renderer answers print-js results back through CefProcessMessage.
#ifndef LETHE_BROWSER_APP_CEF_AUTOMATION_H
#define LETHE_BROWSER_APP_CEF_AUTOMATION_H

#import <Cocoa/Cocoa.h>
#include <chrono>
#include <functional>
#include <mutex>

#include <memory>
#include <string>
#include <vector>

#include "include/cef_browser.h"
#include "app/cef_browser_client.h"

@class LetheCefAppDelegate;

class LetheCefAutomation {
 public:
    static LetheCefAutomation* shared();
    void Start(LetheCefAppDelegate* delegate, const std::string& scriptPath);
    CefRefPtr<CefBrowser> browser() const { return browser_; }
    void set_browser(CefRefPtr<CefBrowser> b) { browser_ = b; }
    void OnBrowserCreated(CefRefPtr<CefBrowser> browser);
    void OnBrowserClosed(CefRefPtr<CefBrowser> browser);
    void ClearPendingNavigation() { pending_navigation_url_.clear(); }
    // Called by CefBrowserClient when a print-js result lands; advances the
    // command queue on the next event-loop tick.
    void OnResult(const std::string& reqId, const std::string& text);
    void OnDevToolsScreenshot(bool success, const std::string& base64);
    void Stop(int exitCode);
    // True once a script ran (even a failing one) - the app delegate tears
    // CEF down right after the CEF loop returns instead of waiting for
    // NSApplication termination.
    bool hasRun() const { return hasRun_; }
    // Exit code recorded by the last Stop(); the app delegate exits with it
    // after CefShutdown so the bench harness sees pass/fail.
    int exitCode() const { return exitCode_; }

 private:
    LetheCefAutomation() = default;
    void Next();
    void RunLine(const std::string& line);
    void LoadWhenReady(const std::string& url, int attempt);
    void EvalAndPrint(const std::string& code);
    void EvalAndPrintPoll(const std::string& id,
                          std::chrono::steady_clock::time_point deadline);
    void WaitForLoad(double ms, bool soft);
    void WaitJs(double ms, const std::string& code);
    void Eval(const std::string& code,
              const std::function<void(const std::string&, bool)>& completion,
              int timeoutMs = 5000);
    void PollEvalResult(const std::string& id,
                        std::chrono::steady_clock::time_point deadline,
                        int timeoutMs);
    bool IsTruthy(const std::string& value) const;
    void ScheduleNext();
    void Fail(const std::string& what);
    void Pass(const std::string& what);
    void StartDevToolsScreenshot(const std::string& path);

    CefRefPtr<CefBrowser> browser_;
    std::vector<CefRefPtr<CefBrowser>> browsers_;
    LetheCefAppDelegate* delegate_ = nullptr;
    std::string script_;
    size_t index_ = 0;
    int failures_ = 0;
    // Result of the last print-js: drained by Next() on the next tick.
    std::string last_result_;
    bool have_result_ = false;
    bool waiting_ = false;
    bool waiting_for_close_ = false;
    bool hasRun_ = false;
    int exitCode_ = 0;
    bool reader_active_ = false;
    std::string pending_eval_id_;
    std::function<void(const std::string&, bool)> pending_eval_callback_;
    std::mutex pending_eval_mtx_;
    // Set before LoadURL so a `wait` immediately following `load` does not
    // race OnLoadStart. CEF may defer the navigation while proxy auth and
    // browser-info initialization settle; in that window main_loading_ is
    // still false even though a navigation is pending.
    std::string pending_navigation_url_;
    std::string pending_navigation_previous_url_;
    CefRefPtr<CefRegistration> screenshot_registration_;
    int pending_screenshot_id_ = 0;
    std::string pending_screenshot_path_;
};

#endif  // LETHE_BROWSER_APP_CEF_AUTOMATION_H
