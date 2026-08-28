// e2e_driver.cc - scripted end-to-end driver for the GTK shell (see header)

#include "e2e_driver.h"

#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>

namespace lethe {

namespace {

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
    return s.substr(b, e - b);
}

std::string jsonString(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            default: out += c;
        }
    }
    return out + "\"";
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

template <typename F>
void timeout(unsigned ms, F fn) {
    auto* heap = new F(std::move(fn));
    g_timeout_add(ms, [](gpointer d) -> gboolean {
        auto* f = static_cast<F*>(d);
        (*f)();
        delete f;
        return G_SOURCE_REMOVE;
    }, heap);
}

} // namespace

E2eDriver::E2eDriver(MainWindow* window, std::string scriptPath) : window_(window), primary_(window) {
    // When the active (Oblivion) window closes, the script continues in the
    // primary window - like a user's attention would.
    MainWindow::setWindowClosedCallback([this](MainWindow* closed) {
        if (closed == window_) { window_ = primary_; current_ = nullptr; }
    });
    std::ifstream in(scriptPath);
    if (!in) {
        std::cerr << "[e2e] cannot read script " << scriptPath << std::endl;
        failures_ = 1;
    }
    std::string line;
    while (std::getline(in, line)) lines_.push_back(line);
}

void E2eDriver::start() {
    current_ = window_->currentTab();
    std::cout << "[e2e] start: " << lines_.size() << " lines" << std::endl;
    later(300);
}

void E2eDriver::later(unsigned ms) { timeout(ms, [this]() { next(); }); }

void E2eDriver::finish(const char* msg) {
    std::cout << "[e2e] " << msg << (failures_ ? " (FAILED)" : " (PASSED)") << std::endl;
    std::cout.flush();
    gtk_main_quit();
    // main() reads the exit code from LETHE_E2E_EXIT after gtk_main returns.
    setenv("LETHE_E2E_EXIT", failures_ ? "1" : "0", 1);
}

void E2eDriver::pass(const std::string& what) { std::cout << "[e2e] ok   " << what << std::endl; }

void E2eDriver::fail(const std::string& what) {
    failures_++;
    std::cout << "[e2e] FAIL line " << index_ << ": " << what << std::endl;
    const char* tmp = g_get_tmp_dir();
    const std::string path = std::string(tmp ? tmp : "/tmp") + "/lethe-e2e-failure.png";
    if (screenshot(path)) std::cout << "[e2e] failure screenshot: " << path << std::endl;
    finish("stopped on first failure");
}

bool E2eDriver::screenshot(const std::string& path) {
    GtkWidget* w = window_->getWidget();
    GdkWindow* gw = w ? gtk_widget_get_window(w) : nullptr;
    if (!gw) return false;
    const int width = gdk_window_get_width(gw), height = gdk_window_get_height(gw);
    GdkPixbuf* pix = gdk_pixbuf_get_from_window(gw, 0, 0, width, height);
    if (!pix) return false;
    GError* err = nullptr;
    const bool ok = gdk_pixbuf_save(pix, path.c_str(), "png", &err, nullptr);
    if (!ok && err) { std::cerr << "[e2e] screenshot: " << err->message << std::endl; g_error_free(err); }
    g_object_unref(pix);
    return ok;
}

void E2eDriver::next() {
    // The current tab follows the notebook's selection (new tabs select
    // themselves; closing selects a neighbour), like a user's eyes would.
    current_ = window_->currentTab();
    while (index_ < lines_.size()) {
        const std::string line = trim(lines_[index_++]);
        if (line.empty() || line[0] == '#') continue;
        run(line);
        return;
    }
    finish("script complete");
}

void E2eDriver::waitForIdle(double timeoutMs, double minMs, gint64 startedUs) {
    const double elapsed = (g_get_monotonic_time() - startedUs) / 1000.0;
    if (elapsed >= minMs && !window_->busy(current_)) { later(250); return; }
    if (elapsed > timeoutMs) { fail("wait: still loading after " + std::to_string((int)timeoutMs) + " ms"); return; }
    timeout(100, [this, timeoutMs, minMs, startedUs]() { waitForIdle(timeoutMs, minMs, startedUs); });
}

void E2eDriver::evaluate(const std::string& js, std::function<void(std::string, bool)> done) {
#if defined(HAVE_FULLWEB)
    WebKitWebView* web = window_->webView(current_);
    if (!web) { done("no web view", false); return; }
    auto* cb = new std::function<void(std::string, bool)>(std::move(done));
    auto finishCb = [](GObject* src, GAsyncResult* res, gpointer data) {
        auto* fn = static_cast<std::function<void(std::string, bool)>*>(data);
        GError* err = nullptr;
        std::string out;
        bool ok = true;
#if WEBKIT_CHECK_VERSION(2, 40, 0)
        JSCValue* value = webkit_web_view_evaluate_javascript_finish(WEBKIT_WEB_VIEW(src), res, &err);
        if (!value) { ok = false; out = err ? err->message : "javascript failed"; }
        else {
            if (jsc_value_is_boolean(value)) out = jsc_value_to_boolean(value) ? "true" : "false";
            else if (jsc_value_is_null(value) || jsc_value_is_undefined(value)) out = "";
            else { gchar* s = jsc_value_to_string(value); out = s ? s : ""; g_free(s); }
            g_object_unref(value);
        }
#else
        WebKitJavascriptResult* r = webkit_web_view_run_javascript_finish(WEBKIT_WEB_VIEW(src), res, &err);
        if (!r) { ok = false; out = err ? err->message : "javascript failed"; }
        else {
            JSCValue* value = webkit_javascript_result_get_js_value(r);
            if (jsc_value_is_boolean(value)) out = jsc_value_to_boolean(value) ? "true" : "false";
            else if (jsc_value_is_null(value) || jsc_value_is_undefined(value)) out = "";
            else { gchar* s = jsc_value_to_string(value); out = s ? s : ""; g_free(s); }
            webkit_javascript_result_unref(r);
        }
#endif
        if (err) g_error_free(err);
        (*fn)(out, ok);
        delete fn;
    };
#if WEBKIT_CHECK_VERSION(2, 40, 0)
    webkit_web_view_evaluate_javascript(web, js.c_str(), -1, nullptr, nullptr, nullptr, finishCb, cb);
#else
    webkit_web_view_run_javascript(web, js.c_str(), nullptr, finishCb, cb);
#endif
#else
    (void)js;
    done("no web engine", false);
#endif
}

void E2eDriver::softWait(double timeoutMs, gint64 startedUs) {
    const double elapsed = (g_get_monotonic_time() - startedUs) / 1000.0;
    if (elapsed >= 300 && !window_->busy(current_)) { later(250); return; }
    if (elapsed > timeoutMs) {
        std::cout << "[e2e] timeout try-wait: still loading after " << (int)timeoutMs << " ms" << std::endl;
        window_->stop(current_);
        later(250);
        return;
    }
    timeout(100, [this, timeoutMs, startedUs]() { softWait(timeoutMs, startedUs); });
}

void E2eDriver::pollJs(const std::string& code, gint64 deadlineUs, double timeoutMs) {
    evaluate(code, [this, code, deadlineUs, timeoutMs](std::string r, bool ok) {
        const bool truthy = ok && !r.empty() && r != "false" && r != "0" && r != "null" && r != "undefined";
        if (truthy) { lastJs_ = r; pass("wait-js -> " + r); next(); return; }
        if (g_get_monotonic_time() >= deadlineUs) {
            fail("wait-js '" + code + "' still falsy after " + std::to_string((int)timeoutMs) + " ms (" + r + ")");
            return;
        }
        timeout(500, [this, code, deadlineUs, timeoutMs]() { pollJs(code, deadlineUs, timeoutMs); });
    });
}

void E2eDriver::run(const std::string& line) {
    const size_t sp = line.find(' ');
    const std::string cmd = sp == std::string::npos ? line : line.substr(0, sp);
    const std::string arg = sp == std::string::npos ? "" : trim(line.substr(sp + 1));
    std::cout << "[e2e] > " << line << std::endl;

    if (cmd == "load") { window_->loadAddress(current_, arg); later(50); }
    else if (cmd == "type-address") {
        window_->focusAddressBar();
        window_->loadAddress(current_, arg);
        later(50);
    }
    else if (cmd == "wait") {
        const double ms = arg.empty() ? 20000 : std::atof(arg.c_str());
        waitForIdle(ms, 300, g_get_monotonic_time());
    }
    else if (cmd == "try-wait") {
        const double ms = arg.empty() ? 20000 : std::atof(arg.c_str());
        softWait(ms, g_get_monotonic_time());
    }
    else if (cmd == "sleep") later(static_cast<unsigned>(std::max(0, std::atoi(arg.c_str()))));
    else if (cmd == "newtab") { current_ = window_->newTab(arg); later(100); }
    else if (cmd == "oblivion") {
        window_ = window_->openOblivionWindow(arg);
        current_ = window_->currentTab();
        later(150);
    }
    else if (cmd == "assert-oblivion") {
        const bool want = arg == "on";
        if (window_->isOblivion() == want) { pass("oblivion state"); next(); }
        else fail(std::string("oblivion ") + (window_->isOblivion() ? "on" : "off"));
    }
    else if (cmd == "closetab") { window_->closeTab(current_); current_ = nullptr; later(200); }
    else if (cmd == "back") { window_->goBack(current_); later(50); }
    else if (cmd == "forward") { window_->goForward(current_); later(50); }
    else if (cmd == "reload") { window_->reload(current_); later(50); }
    else if (cmd == "reader") { window_->toggleReader(current_); later(50); }
    else if (cmd == "click") {
        evaluate("(function(){var e=document.querySelector(" + jsonString(arg) +
                 ");if(!e)return 'missing';e.click();return 'clicked';})()",
                 [this, arg](std::string r, bool ok) {
            if (!ok || r != "clicked") fail("click " + arg + ": " + r); else later(50);
        });
    }
    else if (cmd == "js") {
        evaluate(arg, [this](std::string r, bool ok) {
            if (!ok) { fail("js: " + r); return; }
            lastJs_ = r; next();
        });
    }
    else if (cmd == "wait-js") {
        const size_t sp2 = arg.find(' ');
        if (sp2 == std::string::npos) { fail("wait-js needs <timeout-ms> <code>"); return; }
        const double ms = std::atof(arg.substr(0, sp2).c_str());
        const std::string code = trim(arg.substr(sp2 + 1));
        pollJs(code, g_get_monotonic_time() + static_cast<gint64>(ms * 1000), ms);
    }
    else if (cmd == "print-js") {
        evaluate(arg, [this](std::string r, bool ok) {
            if (!ok) { fail("print-js: " + r); return; }
            lastJs_ = r;
            std::cout << "[e2e] result " << r << std::endl;
            next();
        });
    }
    else if (cmd == "mark") {
        std::cout << "[e2e] mark " << arg << std::endl;
        next();
    }
    else if (cmd == "screenshot") {
        std::string path = arg;
        if (path.rfind("$TMPDIR/", 0) == 0) {
            const char* tmp = g_get_tmp_dir();
            path = std::string(tmp ? tmp : "/tmp") + "/" + path.substr(8);
        }
        timeout(200, [this, path]() {
            const std::string arg = path;
            if (screenshot(arg)) { pass("screenshot " + arg); next(); }
            else fail("screenshot failed");
        });
    }
    else if (cmd == "assert-url-contains") {
        const std::string url = window_->currentUrl(current_);
        const std::string shown = window_->addressText();
        if (contains(url, arg) || contains(shown, arg)) { pass("url " + url); next(); }
        else fail("url '" + url + "' (shown '" + shown + "') lacks '" + arg + "'");
    }
    else if (cmd == "assert-title-contains") {
        const std::string t = window_->currentTitle(current_);
        if (contains(lower(t), lower(arg))) { pass("title '" + t + "'"); next(); }
        else fail("title '" + t + "' lacks '" + arg + "'");
    }
    else if (cmd == "assert-body-contains") {
        evaluate("document.body ? document.body.innerText : ''", [this, arg](std::string body, bool ok) {
            if (ok && contains(body, arg)) { pass("body contains '" + arg + "'"); next(); }
            else fail("body lacks '" + arg + "' (" + body.substr(0, 200) + ")");
        });
    }
    else if (cmd == "assert-tabs") {
        const size_t n = window_->tabCount();
        if (static_cast<int>(n) == std::atoi(arg.c_str())) { pass(std::to_string(n) + " tabs"); next(); }
        else fail("tabs=" + std::to_string(n) + " expected " + arg);
    }
    else if (cmd == "assert-reader") {
        const bool want = arg == "on";
        if (window_->readerActive(current_) == want) { pass("reader state"); next(); }
        else fail(std::string("reader ") + (window_->readerActive(current_) ? "on" : "off"));
    }
    else if (cmd == "assert-js") {
        evaluate(arg, [this, arg](std::string r, bool ok) {
            const bool truthy = ok && !r.empty() && r != "false" && r != "0" && r != "null" && r != "undefined";
            if (truthy) { pass("js -> " + r); next(); } else fail("assert-js '" + arg + "' -> " + r);
        });
    }
    else if (cmd == "quit") finish("quit");
    else fail("unknown command '" + cmd + "'");
}

} // namespace lethe
