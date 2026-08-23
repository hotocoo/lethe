#ifndef LETHE_UI_MAIN_WINDOW_H
#define LETHE_UI_MAIN_WINDOW_H

#include <gtk/gtk.h>
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
    
    GtkWidget* getWidget() { return window_; }

private:
    friend void on_window_destroy(GtkWidget* widget, gpointer data);
    friend void on_entry_activate(GtkWidget* widget, gpointer data);
    friend void on_focus_mode_activate(GtkWidget* widget, gpointer data);

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
};

} // namespace lethe

#endif // LETHE_UI_MAIN_WINDOW_H
