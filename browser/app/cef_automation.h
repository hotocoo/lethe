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

#include <memory>
#include <string>

#include "include/cef_browser.h"
#include "app/cef_browser_client.h"

@class LetheCefAppDelegate;

class LetheCefAutomation {
 public:
    static LetheCefAutomation* shared();
    void Start(LetheCefAppDelegate* delegate, const std::string& scriptPath);
    CefRefPtr<CefBrowser> browser() const { return browser_; }
    void set_browser(CefRefPtr<CefBrowser> b) { browser_ = b; }
    // Called by CefBrowserClient when a print-js result lands; advances the
    // command queue on the next event-loop tick.
    void OnResult(const std::string& text);
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
    void ScheduleNext();
    void Fail(const std::string& what);
    void Pass(const std::string& what);

    CefRefPtr<CefBrowser> browser_;
    LetheCefAppDelegate* delegate_ = nullptr;
    std::string script_;
    size_t index_ = 0;
    int failures_ = 0;
    // Result of the last print-js: drained by Next() on the next tick.
    std::string last_result_;
    bool have_result_ = false;
    bool waiting_ = false;
    bool hasRun_ = false;
    int exitCode_ = 0;
};

#endif  // LETHE_BROWSER_APP_CEF_AUTOMATION_H
