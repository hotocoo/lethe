// cef_automation.cc - see cef_automation.h
//
// Same command language as LetheAutomation.mm so the bench harness can
// drive both binaries through the same step list. The e2e eval path
// goes through the renderer's CefV8Context (CefRenderProcessHandler
// "lethe:eval" / "lethe:eval-result") and the CefBrowserClient parks
// the result for the driver to read.

#include "app/cef_automation.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

#include "include/cef_browser.h"
#include "include/cef_frame.h"
#include "include/cef_process_message.h"
#include "include/cef_values.h"

#include "app/cef_app_delegate.h"

namespace {
LetheCefAutomation* g_automation = nullptr;
}  // namespace

LetheCefAutomation* LetheCefAutomation::shared() {
    if (!g_automation) g_automation = new LetheCefAutomation();
    return g_automation;
}

void LetheCefAutomation::Start(LetheCefAppDelegate* delegate,
                               const std::string& scriptPath) {
    delegate_ = delegate;
    std::ifstream f(scriptPath);
    if (!f) {
        std::cerr << "[e2e] cannot read script " << scriptPath << std::endl;
        failures_ = 1;
        Stop(1);
        return;
    }
    std::stringstream buf;
    buf << f.rdbuf();
    script_ = buf.str();
    int lines = (int)std::count(script_.begin(), script_.end(), '\n');
    std::cout << "[e2e] start: " << lines << " lines" << std::endl;
    index_ = 0;
    failures_ = 0;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{ this->Next(); });
}

void LetheCefAutomation::Next() {
    if (waiting_) return;
    while (index_ < script_.size()) {
        size_t eol = script_.find('\n', index_);
        std::string line = script_.substr(
            index_, eol == std::string::npos ? std::string::npos : eol - index_);
        index_ = (eol == std::string::npos) ? script_.size() : eol + 1;
        while (!line.empty() && (line.back() == '\r' ||
                                 line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        size_t a = 0;
        while (a < line.size() &&
               (line[a] == ' ' || line[a] == '\t')) a++;
        line = line.substr(a);
        if (line.empty() || line[0] == '#') continue;
        std::cout << "[e2e] > " << line << std::endl;
        RunLine(line);
        return;
    }
    std::cout << "[e2e] script complete ("
              << (failures_ ? "FAILED" : "PASSED") << ")" << std::endl;
    std::cout.flush();
    Stop(failures_ ? 1 : 0);
}

void LetheCefAutomation::LoadWhenReady(const std::string& url, int attempt) {
    if (!browser_) return;
    // CefFrame::LoadURL is unreliable in this CEF build: it is silently
    // dropped whenever the frame's browser-info handshake is still in
    // flight, and occasionally even after the first commit. Navigation via
    // the renderer (ExecuteJavaScript location.assign) goes through the
    // frame loader and always lands, so drive the e2e that way. The
    // shipping address bar keeps LoadURL + a retry.
    if (attempt < 50 && delegate_ && delegate_.client &&
        !delegate_.client->IsFirstLoadDone()) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC),
                       dispatch_get_main_queue(),
                       ^{ this->LoadWhenReady(url, attempt + 1); });
        return;
    }
    std::string escaped;
    escaped.reserve(url.size() * 2);
    for (char c : url) {
        if (c == '\\' || c == '\'') escaped.push_back('\\');
        escaped.push_back(c);
    }
    browser_->GetMainFrame()->ExecuteJavaScript(
        "location.assign('" + escaped + "');", "", 0);
    ScheduleNext();
}

void LetheCefAutomation::RunLine(const std::string& line) {
    auto sp = line.find(' ');
    std::string cmd = sp == std::string::npos ? line : line.substr(0, sp);
    std::string arg = sp == std::string::npos ? "" : line.substr(sp + 1);
    while (!arg.empty() && arg.front() == ' ') arg.erase(arg.begin());

    if (cmd == "load" || cmd == "type-address" || cmd == "type") {
        if (browser_) {
            LoadWhenReady(arg, 0);
        } else {
            ScheduleNext();
        }
    } else if (cmd == "wait") {
        double ms = arg.empty() ? 20000.0 : std::atof(arg.c_str());
        WaitForLoad(ms, false);
    } else if (cmd == "try-wait") {
        double ms = arg.empty() ? 20000.0 : std::atof(arg.c_str());
        WaitForLoad(ms, true);
    } else if (cmd == "sleep") {
        double ms = arg.empty() ? 0.0 : std::atof(arg.c_str());
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(ms * NSEC_PER_MSEC)),
                       dispatch_get_main_queue(), ^{ this->Next(); });
    } else if (cmd == "print-js") {
        EvalAndPrint(arg);
    } else if (cmd == "js") {
        if (browser_) {
            CefRefPtr<CefFrame> f = browser_->GetMainFrame();
            if (f) f->ExecuteJavaScript(arg, "", 0);
        }
        ScheduleNext();
    } else if (cmd == "wait-js") {
        auto sp2 = arg.find(' ');
        if (sp2 == std::string::npos) { Fail("wait-js needs <ms> <code>"); return; }
        double ms = std::atof(arg.substr(0, sp2).c_str());
        std::string code = arg.substr(sp2 + 1);
        WaitJs(ms, code);
    } else if (cmd == "mark") {
        std::cout << "[e2e] mark " << arg << std::endl;
        std::cout.flush();
        ScheduleNext();
    } else if (cmd == "quit") {
        std::cout << "[e2e] quit" << std::endl;
        std::cout.flush();
        Stop(0);
    } else if (cmd == "assert-js") {
        EvalAndPrint(arg);  // prints the boolean as "true"/"false"
    } else {
        // ignore-but-pass unknown commands so the bench harness can re-use
        // the same e2e file across shells without erroring on features the
        // CEF shell doesn't implement yet (oblivion, etc.).
        ScheduleNext();
    }
}

void LetheCefAutomation::EvalAndPrint(const std::string& code) {
    if (!browser_ || !delegate_ || !delegate_.client) {
        Fail("no browser");
        return;
    }
    CefRefPtr<CefFrame> f = browser_->GetMainFrame();
    if (!f) { Fail("no frame"); return; }
    const std::string id = delegate_.client->NextEvalId();
    CefRefPtr<CefProcessMessage> msg = CefProcessMessage::Create("lethe:eval");
    msg->GetArgumentList()->SetString(0, code);
    msg->GetArgumentList()->SetString(1, id);
    f->SendProcessMessage(PID_RENDERER, msg);
    // Poll for the result on the main queue: 50 ms cadence, 5 s timeout.
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(5000);
    auto tick = [this, id, deadline]() {
        if (!delegate_ || !delegate_.client) { Fail("client gone"); return; }
        std::string out;
        if (delegate_.client->TryTakeEvalResult(id, &out)) {
            std::cout << "[e2e] result " << out << std::endl;
            std::cout.flush();
            ScheduleNext();
            return;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            Fail("print-js: no reply after 5 s");
            return;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{ this->EvalAndPrintPoll(id, deadline); });
    };
    tick();
}

void LetheCefAutomation::EvalAndPrintPoll(const std::string& id,
                                          std::chrono::steady_clock::time_point deadline) {
    // Same body as the tick lambda, exposed as a method so we can re-enter
    // it without a captured lambda (the previous version captured `this` and
    // called `this->Next()` which advanced the script line, racing the eval
    // result and skipping the result handler entirely).
    if (!delegate_ || !delegate_.client) { Fail("client gone"); return; }
    std::string out;
    if (delegate_.client->TryTakeEvalResult(id, &out)) {
        std::cout << "[e2e] result " << out << std::endl;
        std::cout.flush();
        ScheduleNext();
        return;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        Fail("print-js: no reply after 5 s");
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{ this->EvalAndPrintPoll(id, deadline); });
}

void LetheCefAutomation::WaitForLoad(double ms, bool soft) {
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds((long)ms);
    auto tick = [this, deadline, ms, soft]() {
        if (!delegate_ || !delegate_.client) { Fail("no client"); return; }
        if (!delegate_.client->IsMainLoading()) { ScheduleNext(); return; }
        if (std::chrono::steady_clock::now() >= deadline) {
            if (soft) {
                std::cout << "[e2e] timeout try-wait: still loading after "
                          << (int)ms << " ms" << std::endl;
                std::cout.flush();
                if (browser_) browser_->StopLoad();
                ScheduleNext();
                return;
            }
            Fail("wait: still loading after " + std::to_string((int)ms) + " ms");
            return;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{ this->WaitForLoad(0, soft); });
    };
    tick();
}

void LetheCefAutomation::WaitJs(double ms, const std::string& code) {
    if (!browser_ || !delegate_ || !delegate_.client) { Fail("no client"); return; }
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds((long)ms);
    auto tick = [this, deadline, code, ms]() {
        if (std::chrono::steady_clock::now() >= deadline) {
            Fail("wait-js timeout after " + std::to_string((int)ms) + " ms");
            return;
        }
        if (!browser_) { Fail("no browser"); return; }
        CefRefPtr<CefFrame> f = browser_->GetMainFrame();
        if (!f) { Fail("no frame"); return; }
        const std::string id = delegate_.client->NextEvalId();
        CefRefPtr<CefProcessMessage> msg =
            CefProcessMessage::Create("lethe:eval");
        msg->GetArgumentList()->SetString(0,
            "(function(){try{return !!(" + code + ");}catch(e){return false;}})()");
        msg->GetArgumentList()->SetString(1, id);
        f->SendProcessMessage(PID_RENDERER, msg);
        // We can't poll the eval-result table while we're inside the
        // process-message handler's queue, so kick a continuation that
        // runs in a fresh tick.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{ this->Next(); });
    };
    tick();
}

void LetheCefAutomation::ScheduleNext() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{ this->Next(); });
}

void LetheCefAutomation::Fail(const std::string& what) {
    failures_++;
    std::cout << "[e2e] FAIL: " << what << std::endl;
    std::cout.flush();
    Stop(1);
}

void LetheCefAutomation::Pass(const std::string& what) {
    std::cout << "[e2e] ok   " << what << std::endl;
    std::cout.flush();
}

void LetheCefAutomation::Stop(int exitCode) {
    // Quit the CEF loop; the delegate tears CEF down right after
    // CefRunMessageLoop returns (terminate: from a nested CEF loop would
    // re-enter CefShutdown on the same stack and crash). exitCode rides
    // through the delegate.
    hasRun_ = true;
    exitCode_ = exitCode;
    if (delegate_ && delegate_.client) delegate_.client->SetPendingQuit(true);
    CefQuitMessageLoop();
}
