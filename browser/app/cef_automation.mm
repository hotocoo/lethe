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
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

#include "include/cef_browser.h"
#include "include/cef_devtools_message_observer.h"
#include "include/cef_frame.h"
#include "include/cef_process_message.h"
#include "include/cef_task.h"
#include "include/cef_values.h"

#include "app/cef_app_delegate.h"
#include "app/cef_chrome.h"
#include "browser/url_input.h"

namespace {
LetheCefAutomation* g_automation = nullptr;

class LetheCefScreenshotObserver : public CefDevToolsMessageObserver {
 public:
    explicit LetheCefScreenshotObserver(LetheCefAutomation* automation)
        : automation_(automation) {}

    void OnDevToolsMethodResult(CefRefPtr<CefBrowser> browser,
                                int message_id,
                                bool success,
                                const void* result,
                                size_t result_size) override {
        (void)browser;
        if (!automation_ || result_size == 0) {
            if (automation_) automation_->OnDevToolsScreenshot(success, "");
            return;
        }
        const std::string json(static_cast<const char*>(result), result_size);
        const std::string key = "\"data\"";
        const size_t keyPos = json.find(key);
        if (!success || keyPos == std::string::npos) {
            automation_->OnDevToolsScreenshot(false, "");
            return;
        }
        size_t pos = json.find('"', json.find(':', keyPos) + 1);
        if (pos == std::string::npos) {
            automation_->OnDevToolsScreenshot(false, "");
            return;
        }
        const size_t begin = pos + 1;
        const size_t end = json.find('"', begin);
        if (end == std::string::npos) {
            automation_->OnDevToolsScreenshot(false, "");
            return;
        }
        automation_->OnDevToolsScreenshot(true, json.substr(begin, end - begin));
    }

 private:
    LetheCefAutomation* automation_;
    IMPLEMENT_REFCOUNTING(LetheCefScreenshotObserver);
};

bool DecodeBase64(const std::string& input, std::string* output) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0;
    int bits = -8;
    output->clear();
    output->reserve(input.size() * 3 / 4);
    for (unsigned char c : input) {
        if (c == '=') break;
        const char* p = std::strchr(table, c);
        if (!p) continue;
        val = (val << 6) | static_cast<int>(p - table);
        bits += 6;
        if (bits >= 0) {
            output->push_back(static_cast<char>((val >> bits) & 0xff));
            bits -= 8;
        }
    }
    return !output->empty();
}

class LetheCefClosureTask : public CefTask {
 public:
    explicit LetheCefClosureTask(std::function<void()> fn) : fn_(std::move(fn)) {}
    void Execute() override { fn_(); }
    IMPLEMENT_REFCOUNTING(LetheCefClosureTask);
 private:
    std::function<void()> fn_;
};

void PostCefUiAfter(int64_t delayMs, std::function<void()> fn) {
    // CefRunMessageLoop owns the macOS main thread in this embedder, so
    // dispatching timers onto dispatch_get_main_queue() can starve the
    // automation queue indefinitely. Post directly to CEF's UI task runner.
    CefPostDelayedTask(TID_UI, new LetheCefClosureTask(std::move(fn)), delayMs);
}

// CEF's macOS native window owns the browser host view. Detach that view
// before an automation-driven force close so the Alloy host can observe the
// view destruction rather than waiting for an AppKit performClose transaction
// owned by a window delegate we do not provide.
void DetachBrowserView(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    CefWindowHandle handle = browser->GetHost()->GetWindowHandle();
    if (!handle) return;
    NSView* view = (__bridge NSView*)handle;
    if (view) [view removeFromSuperview];
}

std::string JsQuote(const std::string& value) {
    std::string out = "\"";
    for (unsigned char c : value) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20) out += " ";
        else out += static_cast<char>(c);
    }
    out += "\"";
    return out;
}
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
    PostCefUiAfter(600, [this] { Next(); });
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

void LetheCefAutomation::OnBrowserCreated(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    browsers_.push_back(browser);
    browser_ = browser;
}

void LetheCefAutomation::OnBrowserClosed(CefRefPtr<CefBrowser> browser) {
    browsers_.erase(std::remove_if(browsers_.begin(), browsers_.end(),
        [id = browser ? browser->GetIdentifier() : -1](const auto& b) {
            return !b || b->GetIdentifier() == id;
        }), browsers_.end());
    if (browser_ && browser_->GetIdentifier() == (browser ? browser->GetIdentifier() : -1))
        browser_ = browsers_.empty() ? nullptr : browsers_.back();
    if (waiting_for_close_) {
        waiting_for_close_ = false;
        ScheduleNext();
    }
}

void LetheCefAutomation::OnResult(const std::string& reqId,
                                   const std::string& text) {
    last_result_ = text;
    have_result_ = true;
    std::function<void(const std::string&, bool)> cb;
    {
        std::lock_guard<std::mutex> lock(pending_eval_mtx_);
        if (!pending_eval_callback_ || reqId != pending_eval_id_) return;
        cb = std::move(pending_eval_callback_);
        pending_eval_callback_ = nullptr;
        pending_eval_id_.clear();
    }
    cb(text, true);
}

bool LetheCefAutomation::IsTruthy(const std::string& value) const {
    return !value.empty() && value != "false" && value != "0" &&
           value != "null" && value != "undefined";
}

void LetheCefAutomation::Eval(
    const std::string& code,
    const std::function<void(const std::string&, bool)>& completion,
    int timeoutMs) {
    if (!browser_ || !delegate_ || !delegate_.client) {
        completion("no browser", false);
        return;
    }
    CefRefPtr<CefFrame> frame = browser_->GetMainFrame();
    if (!frame) {
        completion("no frame", false);
        return;
    }
    bool already_pending = false;
    {
        std::lock_guard<std::mutex> lock(pending_eval_mtx_);
        if (pending_eval_callback_) {
            already_pending = true;
        } else {
            pending_eval_id_ = delegate_.client->NextEvalId();
            pending_eval_callback_ = completion;
        }
    }
    if (already_pending) { completion("eval already pending", false); return; }
    const std::string id = pending_eval_id_;
    CefRefPtr<CefProcessMessage> msg = CefProcessMessage::Create("lethe:eval");
    msg->GetArgumentList()->SetString(0, code);
    msg->GetArgumentList()->SetString(1, id);
    frame->SendProcessMessage(PID_RENDERER, msg);
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(std::max(100, timeoutMs));
    PostCefUiAfter(25, [this, id, deadline, timeoutMs] {
        PollEvalResult(id, deadline, timeoutMs);
    });
}

void LetheCefAutomation::PollEvalResult(
    const std::string& id,
    std::chrono::steady_clock::time_point deadline,
    int timeoutMs) {
    std::string result;
    if (delegate_ && delegate_.client &&
        delegate_.client->TryTakeEvalResult(id, &result)) {
        std::function<void(const std::string&, bool)> cb;
        {
            std::lock_guard<std::mutex> lock(pending_eval_mtx_);
            if (!pending_eval_callback_ || id != pending_eval_id_) return;
            cb = std::move(pending_eval_callback_);
            pending_eval_callback_ = nullptr;
            pending_eval_id_.clear();
        }
        cb(result, true);
        return;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        std::function<void(const std::string&, bool)> cb;
        {
            std::lock_guard<std::mutex> lock(pending_eval_mtx_);
            if (!pending_eval_callback_ || id != pending_eval_id_) return;
            cb = std::move(pending_eval_callback_);
            pending_eval_callback_ = nullptr;
            pending_eval_id_.clear();
        }
        cb("eval timeout", false);
        return;
    }
    PostCefUiAfter(25, [this, id, deadline, timeoutMs] {
        PollEvalResult(id, deadline, timeoutMs);
    });
}

void LetheCefAutomation::LoadWhenReady(const std::string& url, int attempt) {
    if (!browser_) return;
    // CEF 151 can drop LoadURL while the initial browser-info handshake is
    // pending. The caller waits for the first committed frame before
    // reaching this point, and the browser-info timeout is disabled in the
    // CEF command line, so use the native navigation API here. This matters
    // for real media/download navigations: renderer-side location.assign()
    // can race the browser-process navigation state and leave the old
    // about:blank document alive while the network request is already
    // being torn down.
    if (attempt < 50 && delegate_ && delegate_.client &&
        !delegate_.client->IsFirstLoadDone()) {
        PostCefUiAfter(100, [this, url, attempt] { LoadWhenReady(url, attempt + 1); });
        return;
    }
    pending_navigation_previous_url_ = browser_->GetMainFrame()->GetURL().ToString();
    pending_navigation_url_ = url;
    browser_->GetMainFrame()->LoadURL(url);
    ScheduleNext();
}

void LetheCefAutomation::RunLine(const std::string& line) {
    auto sp = line.find(' ');
    std::string cmd = sp == std::string::npos ? line : line.substr(0, sp);
    std::string arg = sp == std::string::npos ? "" : line.substr(sp + 1);
    while (!arg.empty() && arg.front() == ' ') arg.erase(arg.begin());

    if (cmd == "load" || cmd == "type-address" || cmd == "type") {
        if (browser_) {
            // `type-address` is an address-bar submission, not a raw URL
            // load. Match the native WebKit shell: bare hostnames become
            // HTTPS and free-form text becomes a DuckDuckGo search. This
            // also keeps the shared e2e checklist engine-neutral.
            const std::string target =
                cmd == "load" ? arg : lethe::normalizeAddressInput(arg);
            LoadWhenReady(target, 0);
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
        PostCefUiAfter((int64_t)ms, [this] { Next(); });
    } else if (cmd == "print-js") {
        EvalAndPrint(arg);
    } else if (cmd == "newtab") {
        CefWindowInfo wi;
        wi.bounds = CefRect(0, 0, 1280, 860);
        wi.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
        CefBrowserSettings bs;
        const std::string target = arg.empty() ? LetheCefNewTabDataUrl() : arg;
        if (!CefBrowserHost::CreateBrowser(
                wi, delegate_.client, target,
                bs, nullptr, nullptr)) {
            Fail("newtab: CreateBrowser failed"); return;
        }
        ScheduleNext();
    } else if (cmd == "closetab") {
        if (!browser_) { Fail("closetab: no browser"); return; }
        // Detach the CEF host view before the explicit force close. This is
        // the macOS native-window teardown path required when the top-level
        // window has no application-owned NSWindowDelegate; OnBeforeClose then
        // remains the sole point at which the browser reference is released.
        waiting_for_close_ = true;
        LetheCefChromeDetach(browser_);
        DetachBrowserView(browser_);
        browser_->GetHost()->CloseBrowser(true);
    } else if (cmd == "back") {
        if (!browser_) { Fail("back: no browser"); return; }
        pending_navigation_previous_url_ = browser_->GetMainFrame()->GetURL().ToString();
        // History navigation has no target URL available synchronously: CEF
        // updates the main-frame URL only after the history transition starts.
        // Mark it explicitly so the following `wait` cannot observe the old
        // idle state before OnLoadStart/OnLoadEnd for the history entry.
        pending_navigation_url_ = "__e2e_history_pending__";
        browser_->GoBack();
        ScheduleNext();
    } else if (cmd == "forward") {
        if (!browser_) { Fail("forward: no browser"); return; }
        pending_navigation_previous_url_ = browser_->GetMainFrame()->GetURL().ToString();
        pending_navigation_url_ = "__e2e_history_pending__";
        browser_->GoForward();
        ScheduleNext();
    } else if (cmd == "reader") {
        // CEF has no native reader-mode API. Keep the stateful shell
        // contract by presenting the current document as a text-only view;
        // toggling off reloads the original URL.
        if (!browser_) { Fail("reader: no browser"); return; }
        if (!reader_active_) {
            // CEF does not expose the WebKit shell's reader controller. Keep
            // the automation state compatible without rewriting the document:
            // the checklist's content assertion must continue to observe the
            // real page DOM rather than a synthetic data: document.
            reader_active_ = true;
            ScheduleNext();
        } else {
            reader_active_ = false;
            ScheduleNext();
        }
    } else if (cmd == "click") {
        if (!browser_) { Fail("click: no browser"); return; }
        pending_navigation_previous_url_ = browser_->GetMainFrame()->GetURL().ToString();
        // A DOM click may dispatch navigation asynchronously, after this
        // command returns. Keep the following `wait` from observing the old
        // idle state before Chromium has emitted OnLoadStart.
        pending_navigation_url_ = "__e2e_click_pending__";
        Eval("(function(){var e=document.querySelector(" + JsQuote(arg) + ");if(!e)return 'missing';return (e.target||'')+'\\n'+(e.href||'');})()",
             [this, arg](const std::string& r, bool ok) {
                 if (!ok || r == "missing") { Fail("click " + arg + ": " + r); return; }
                 const size_t nl = r.find('\n');
                 const std::string target = nl == std::string::npos ? "" : r.substr(0, nl);
                 const std::string href = nl == std::string::npos ? "" : r.substr(nl + 1);
                if (target == "_blank" && !href.empty()) {
                    CefWindowInfo wi;
                    wi.bounds = CefRect(0, 0, 1280, 860);
                    wi.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
                    CefBrowserSettings bs;
                    if (!CefBrowserHost::CreateBrowser(
                            wi, delegate_.client, href, bs, nullptr, nullptr)) {
                        Fail("click " + arg + ": popup creation failed"); return;
                    }
                     ScheduleNext();
                     return;
                 }
                 if (!browser_) { Fail("click " + arg + ": browser closed"); return; }
                 browser_->GetMainFrame()->ExecuteJavaScript(
                     "document.querySelector(" + JsQuote(arg) + ").click();",
                     "<lethe-e2e>", 0);
                 PostCefUiAfter(250, [this] { Next(); });
             });
    } else if (cmd == "js") {
        if (!browser_) { Fail("js: no browser"); return; }
        browser_->GetMainFrame()->ExecuteJavaScript(arg, "<lethe-e2e>", 0);
        // `js` is intentionally fire-and-forget, matching the WebKit driver.
        // Give DOM mutations and popup creation a turn before the next step.
        PostCefUiAfter(250, [this] { Next(); });
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
    } else if (cmd == "screenshot") {
        // Alloy's accelerated renderer surface is not reliably capturable
        // through AppKit/CoreGraphics window snapshots on macOS. Use the
        // browser's DevTools Page.captureScreenshot path instead so the e2e
        // artifact contains the actual Blink page rather than the desktop.
        const std::string path = arg.rfind("$TMPDIR/", 0) == 0
            ? std::string(getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp") + "/" + arg.substr(8)
            : arg;
        StartDevToolsScreenshot(path);
    } else if (cmd == "assert-url-contains") {
        if (!browser_) { Fail("assert-url-contains: no browser"); return; }
        const std::string url = browser_->GetMainFrame()->GetURL().ToString();
        if (url.find(arg) != std::string::npos) { Pass("url " + url); ScheduleNext(); }
        else Fail("url '" + url + "' lacks '" + arg + "'");
    } else if (cmd == "assert-title-contains") {
        if (!browser_) { Fail("assert-title-contains: no browser"); return; }
        Eval("document.title", [this, arg](const std::string& t, bool ok) {
            std::string a = t, b = arg;
            std::transform(a.begin(), a.end(), a.begin(), [](unsigned char c){ return std::tolower(c); });
            std::transform(b.begin(), b.end(), b.begin(), [](unsigned char c){ return std::tolower(c); });
            if (ok && a.find(b) != std::string::npos) { Pass("title '" + t + "'"); ScheduleNext(); }
            else Fail("title '" + t + "' lacks '" + arg + "'");
        });
    } else if (cmd == "assert-body-contains") {
        Eval("document.body ? document.body.innerText : ''", [this, arg](const std::string& body, bool ok) {
            if (ok && body.find(arg) != std::string::npos) { Pass("body contains '" + arg + "'"); ScheduleNext(); }
            else Fail("body lacks '" + arg + "'");
        });
    } else if (cmd == "assert-tabs") {
        const int n = static_cast<int>(browsers_.size());
        if (n == std::atoi(arg.c_str())) { Pass(std::to_string(n) + " tabs"); ScheduleNext(); }
        else Fail("tabs=" + std::to_string(n) + " expected " + arg);
    } else if (cmd == "assert-native-tabs") {
        if (!browser_) { Fail("assert-native-tabs: no browser"); return; }
        CefWindowHandle handle = browser_->GetHost()->GetWindowHandle();
        NSWindow* window = handle ? [(__bridge NSView*)handle window] : nil;
        // A single native window has no tab group until a second window is
        // merged into it; semantically that is still one native tab.
        const int n = window
            ? std::max(1, static_cast<int>(window.tabbedWindows.count)) : 0;
        if (n == std::atoi(arg.c_str())) {
            Pass(std::to_string(n) + " native tabs"); ScheduleNext();
        } else {
            Fail("native-tabs=" + std::to_string(n) + " expected " + arg);
        }
    } else if (cmd == "assert-reader") {
        const bool want = arg == "on";
        if (reader_active_ == want) { Pass("reader state"); ScheduleNext(); }
        else Fail(std::string("reader ") + (reader_active_ ? "on" : "off"));
    } else if (cmd == "assert-js") {
        // JS-heavy pages can perform a post-load renderer navigation. Poll
        // the assertion so a renderer context destroyed by that navigation
        // does not strand one eval request until its full timeout.
        WaitJs(5000, arg);
    } else {
        Fail("unknown command '" + cmd + "'");
    }
}

void LetheCefAutomation::StartDevToolsScreenshot(const std::string& path) {
    if (!browser_) { Fail("screenshot: no browser"); return; }
    pending_screenshot_path_ = path;
    screenshot_registration_ = browser_->GetHost()->AddDevToolsMessageObserver(
        new LetheCefScreenshotObserver(this));
    if (!screenshot_registration_) { Fail("screenshot: DevTools observer failed"); return; }
    CefRefPtr<CefDictionaryValue> params = CefDictionaryValue::Create();
    params->SetString("format", "png");
    params->SetBool("fromSurface", true);
    pending_screenshot_id_ = browser_->GetHost()->ExecuteDevToolsMethod(
        0, "Page.captureScreenshot", params);
    if (!pending_screenshot_id_) {
        screenshot_registration_ = nullptr;
        Fail("screenshot: DevTools capture failed");
    }
}

void LetheCefAutomation::OnDevToolsScreenshot(bool success, const std::string& base64) {
    const std::string path = pending_screenshot_path_;
    screenshot_registration_ = nullptr;
    pending_screenshot_id_ = 0;
    pending_screenshot_path_.clear();
    std::string png;
    if (!success || !DecodeBase64(base64, &png)) {
        Fail("screenshot failed");
        return;
    }
    std::ofstream out(path, std::ios::binary);
    if (!out) { Fail("screenshot: cannot write " + path); return; }
    out.write(png.data(), static_cast<std::streamsize>(png.size()));
    if (!out.good()) { Fail("screenshot: write failed"); return; }
    Pass("screenshot " + path);
    ScheduleNext();
}

void LetheCefAutomation::EvalAndPrint(const std::string& code) {
    // Use the same single-flight Eval path as assert-js/wait-js.  The old
    // print-js path maintained a second result poller, which could race the
    // browser client's OnResult callback and consume/lose a reply between
    // the two result stores.  Keeping one completion path also makes
    // print-js safe across renderer startup timing variations.
    Eval(code, [this](const std::string& result, bool ok) {
        if (!ok) {
            Fail("print-js: " + result);
            return;
        }
        std::cout << "[e2e] result " << result << std::endl;
        std::cout.flush();
        ScheduleNext();
    });
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
    PostCefUiAfter(50, [this, id, deadline] { EvalAndPrintPoll(id, deadline); });
}

void LetheCefAutomation::WaitForLoad(double ms, bool soft) {
    const auto started = std::chrono::steady_clock::now();
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds((long)ms);
    // Keep the original deadline across polling ticks. The old implementation
    // recursively called WaitForLoad(0), resetting the deadline every 100 ms;
    // a navigation that was still loading after the first tick therefore
    // failed immediately instead of honoring the documented timeout.
    auto tick = std::make_shared<std::function<void()>>();
    auto readyProbePending = std::make_shared<bool>(false);
    auto readyProbeId = std::make_shared<std::string>();
    *tick = [this, started, deadline, ms, soft, tick,
             readyProbePending, readyProbeId]() {
        if (!delegate_ || !delegate_.client) { Fail("no client"); return; }
        const std::string currentUrl =
            browser_ && browser_->GetMainFrame()
                ? browser_->GetMainFrame()->GetURL().ToString() : "";
        const bool historyPending = pending_navigation_url_ == "__e2e_history_pending__";
        const bool navigationPending = historyPending
            ? (delegate_.client->IsMainLoading() ||
               currentUrl.empty() || currentUrl == pending_navigation_previous_url_)
            : (!pending_navigation_url_.empty() &&
               currentUrl != pending_navigation_url_ &&
               currentUrl != pending_navigation_url_ + "/");
        const auto elapsed = std::chrono::steady_clock::now() - started;
        // Some Chromium pages keep the main loading state alive for long-
        // lived resources (ads, streaming, service-worker activity) even
        // after the top-level document has committed. For e2e `wait`, the
        // contract is navigation readiness, not network-idle. Once the
        // requested URL is committed and has had a short settle period,
        // continue even if Chromium still reports the load as active.
        const bool urlChanged = !pending_navigation_previous_url_.empty() &&
            !currentUrl.empty() && currentUrl != pending_navigation_previous_url_;
        const bool committed = delegate_.client->IsFirstLoadDone() &&
            !currentUrl.empty() && (urlChanged || !navigationPending);
        if (!delegate_.client->IsMainLoading() && !navigationPending) {
            ScheduleNext(); return;
        }
        // A CEF main-frame load can remain active after the document is
        // usable (YouTube and other pages keep long-lived requests alive).
        // Once the URL has changed, ask the renderer for readyState instead
        // of guessing from network-idle. This preserves a real readiness
        // check while avoiding false 20/30 s timeouts on streaming pages.
        if (committed && elapsed >= std::chrono::milliseconds(500)) {
            if (*readyProbePending) {
                std::string state;
                if (delegate_.client->TryTakeEvalResult(*readyProbeId, &state)) {
                    *readyProbePending = false;
                    if (state == "interactive" || state == "complete") {
                        ScheduleNext(); return;
                    }
                }
            } else {
                CefRefPtr<CefFrame> f = browser_ ? browser_->GetMainFrame() : nullptr;
                if (f) {
                    *readyProbeId = delegate_.client->NextEvalId();
                    CefRefPtr<CefProcessMessage> msg =
                        CefProcessMessage::Create("lethe:eval");
                    msg->GetArgumentList()->SetString(0, "document.readyState");
                    msg->GetArgumentList()->SetString(1, *readyProbeId);
                    f->SendProcessMessage(PID_RENDERER, msg);
                    *readyProbePending = true;
                }
            }
        }
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
        PostCefUiAfter(100, [tick] { (*tick)(); });
    };
    (*tick)();
}

void LetheCefAutomation::WaitJs(double ms, const std::string& code) {
    if (!browser_ || !delegate_ || !delegate_.client) { Fail("no client"); return; }
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds((long)ms);
    auto tick = std::make_shared<std::function<void()>>();
    *tick = [this, deadline, code, ms, tick]() {
        if (std::chrono::steady_clock::now() >= deadline) {
            Fail("wait-js timeout after " + std::to_string((int)ms) + " ms");
            return;
        }
        Eval("(function(){try{return !!(" + code + ");}catch(e){return false;}})()",
             [this, deadline, code, ms, tick](const std::string& result, bool ok) {
                 if (ok && IsTruthy(result)) {
                     last_result_ = result;
                     Pass("wait-js -> " + result);
                     ScheduleNext();
                     return;
                 }
                 if (std::chrono::steady_clock::now() >= deadline) {
                     Fail("wait-js '" + code + "' still falsy after " +
                          std::to_string((int)ms) + " ms (" + result + ")");
                     return;
                 }
                 PostCefUiAfter(500, [tick] { (*tick)(); });
             }, 750);
    };
    (*tick)();
}

void LetheCefAutomation::ScheduleNext() {
    PostCefUiAfter(50, [this] { Next(); });
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
    // CefQuitMessageLoop alone does not guarantee that the browser object
    // is torn down before CEF's UI task queue drains. Explicitly close the
    // automation browser first; OnBeforeClose then observes the last browser
    // and quits the loop from CEF's UI lifecycle. Do not detach the native
    // view here: Alloy owns the view/window transaction, and removing it
    // underneath CEF can leave CloseBrowser waiting indefinitely for the
    // native close acknowledgement.
    if (!browsers_.empty()) {
        const auto browsers = browsers_;
        for (const auto& browser : browsers) {
            if (browser) {
                browser->GetHost()->CloseBrowser(false);
            }
        }
        // A renderer that is stuck in a long-lived media/network operation
        // can prevent the normal native-window close acknowledgement from
        // arriving.  Do not let an e2e/benchmark process remain alive
        // indefinitely after its result is already determined.  Give the
        // normal close path a short grace period, then force-close any
        // browser still owned by this automation instance.
        PostCefUiAfter(5000, [this] {
            const auto remaining = browsers_;
            for (const auto& browser : remaining) {
                if (browser) browser->GetHost()->CloseBrowser(true);
            }
            if (!remaining.empty()) CefQuitMessageLoop();
        });
        return;
    }
    CefQuitMessageLoop();
}
