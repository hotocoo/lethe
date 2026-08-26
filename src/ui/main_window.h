#ifndef LETHE_UI_MAIN_WINDOW_H
#define LETHE_UI_MAIN_WINDOW_H

#include <gtk/gtk.h>
#include <functional>
#include <string>
#include "core/engine.h"

namespace lethe {

class MainWindow {
public:
    MainWindow(Engine* engine);
    ~MainWindow();
    
    void create();
    void show();
    void run();
    void quit();

    // Full-web mode hook: invoked with the address-bar URL when the user
    // picks the menu item or hits Ctrl+Shift+W. The app layer owns the
    // FullWebWindow (and its policy plumbing); the window stays decoupled.
    using FullWebCallback = std::function<void(const std::string& url)>;
    void setFullWebCallback(FullWebCallback cb) { fullWebCallback_ = std::move(cb); }
    // Invokes fullWebCallback_ with the current address-bar text.
    void triggerFullWeb();
    
    GtkWidget* getWidget() { return window_; }

private:
    friend void on_window_destroy(GtkWidget* widget, gpointer data);
    friend void on_entry_activate(GtkWidget* widget, gpointer data);
    friend void on_focus_mode_activate(GtkWidget* widget, gpointer data);

    std::string entryText() const { return entry_ ? gtk_entry_get_text(GTK_ENTRY(entry_)) : ""; }

    void setupUI();
    void connectSignals();

    GtkWidget* createMenu();
    // Distraction-free reading: hides address entry and menu button until
    // toggled again (Ctrl+Shift+F or the menu item).
    void toggleFocusMode();

    Engine* engine_;
    GtkWidget* window_;
    GtkWidget* headerBar_;
    GtkWidget* menuButton_;
    GtkWidget* menu_;
    GtkWidget* entry_;
    GtkWidget* box_;
    GtkWidget* tabBox_;
    GtkWidget* scrollWindow_;
    GtkWidget* viewport_;
    GtkAccelGroup* accelGroup_ = nullptr;
    bool focusMode_ = false;
    FullWebCallback fullWebCallback_;
};

} // namespace lethe

#endif // LETHE_UI_MAIN_WINDOW_H
