#ifndef LETHE_UI_E2E_DRIVER_H
#define LETHE_UI_E2E_DRIVER_H

// e2e_driver.h - scripted end-to-end driver for the GTK shell
//
// Same command language as the macOS driver (docs/E2E.md): one command per
// line, assertions stop the run, process exits 0/1. Runs inside the GTK
// main loop; JavaScript and screenshots go through WebKitGTK.

#include <string>
#include <vector>

#include "main_window.h"

namespace lethe {

class E2eDriver {
public:
    E2eDriver(MainWindow* window, std::string scriptPath);
    void start();

private:
    void next();
    void run(const std::string& line);
    void later(unsigned ms);
    void waitForIdle(double timeoutMs, double minMs, gint64 startedUs);
    void evaluate(const std::string& js, std::function<void(std::string, bool ok)> done);
    void pollJs(const std::string& code, gint64 deadlineUs, double timeoutMs);
    void softWait(double timeoutMs, gint64 startedUs);
    void pass(const std::string& what);
    void fail(const std::string& what);
    void finish(const char* msg);
    bool screenshot(const std::string& path);

    MainWindow* window_;           // active window (primary or an Oblivion window)
    MainWindow* primary_;
    std::vector<std::string> lines_;
    size_t index_ = 0;
    int failures_ = 0;
    std::string lastJs_;
    MainWindow::Tab* current_ = nullptr;
};

} // namespace lethe

#endif // LETHE_UI_E2E_DRIVER_H
