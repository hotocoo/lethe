#include "main_window.h"
#include <iostream>
#include <memory>
#include "config.h"

namespace lethe {

static void on_fullweb_activate(GtkWidget*, gpointer data) {
    static_cast<MainWindow*>(data)->triggerFullWeb();
}


// Namespace-scope (not static) so they match the friend declarations in
// MainWindow and can reach private members through the passed pointer.
void on_window_destroy(GtkWidget* widget, gpointer data) {
    (void)widget; (void)data;
    gtk_main_quit();
}

void on_entry_activate(GtkWidget* widget, gpointer data) {
    MainWindow* self = static_cast<MainWindow*>(data);
    const char* text = gtk_entry_get_text(GTK_ENTRY(widget));
    std::string url = text;
    if (!url.empty()) {
        if (self->engine_ && self->engine_->tabManager()) {
            int activeTab = self->engine_->tabManager()->getActiveTab();
            self->engine_->tabManager()->navigate(activeTab, url);
        }
    }
}

void on_focus_mode_activate(GtkWidget* widget, gpointer data) {
    (void)widget;
    static_cast<MainWindow*>(data)->toggleFocusMode();
}

MainWindow::MainWindow(Engine* engine) 
    : engine_(engine), window_(nullptr), headerBar_(nullptr),
      menuButton_(nullptr), menu_(nullptr), entry_(nullptr),
      box_(nullptr), tabBox_(nullptr), scrollWindow_(nullptr),
      viewport_(nullptr) {
}

MainWindow::~MainWindow() {
}

void MainWindow::toggleFocusMode() {
    focusMode_ = !focusMode_;
    if (entry_) gtk_widget_set_visible(entry_, !focusMode_);
    if (menuButton_) gtk_widget_set_visible(menuButton_, !focusMode_);
    std::cout << "[lethe] Focus mode " << (focusMode_ ? "ON" : "OFF")
              << " (Ctrl+Shift+F)" << std::endl;
}

void MainWindow::create() {
    window_ = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window_), "Lethe Browser");
    gtk_window_set_default_size(GTK_WINDOW(window_), 1280, 880);
    gtk_window_set_resizable(GTK_WINDOW(window_), TRUE);

    accelGroup_ = gtk_accel_group_new();
    gtk_window_add_accel_group(GTK_WINDOW(window_), accelGroup_);
    gtk_accel_group_connect(
        accelGroup_, GDK_KEY_f,
        static_cast<GdkModifierType>(GDK_CONTROL_MASK | GDK_SHIFT_MASK),
        GTK_ACCEL_VISIBLE,
        g_cclosure_new(G_CALLBACK(on_focus_mode_activate), this, nullptr));
    gtk_accel_group_connect(
        accelGroup_, GDK_KEY_w,
        static_cast<GdkModifierType>(GDK_CONTROL_MASK | GDK_SHIFT_MASK),
        GTK_ACCEL_VISIBLE,
        g_cclosure_new(G_CALLBACK(on_fullweb_activate), this, nullptr));

    setupUI();
    connectSignals();
}

void MainWindow::setupUI() {
    headerBar_ = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(headerBar_), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(headerBar_), "Lethe");
    gtk_window_set_titlebar(GTK_WINDOW(window_), headerBar_);
    
    menuButton_ = gtk_menu_button_new();
    gtk_menu_button_set_popup(GTK_MENU_BUTTON(menuButton_), createMenu());
    gtk_header_bar_pack_start(GTK_HEADER_BAR(headerBar_), menuButton_);
    
    entry_ = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_), "Enter URL or search...");
    gtk_widget_set_hexpand(entry_, TRUE);
    gtk_widget_set_hexpand_set(entry_, TRUE);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(headerBar_), entry_);
    
    box_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window_), box_);
    
    tabBox_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(box_), tabBox_, FALSE, FALSE, 0);
    
    scrollWindow_ = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollWindow_),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(box_), scrollWindow_, TRUE, TRUE, 0);
    
    viewport_ = gtk_event_box_new();
    gtk_widget_set_hexpand(viewport_, TRUE);
    gtk_widget_set_vexpand(viewport_, TRUE);
    gtk_container_add(GTK_CONTAINER(scrollWindow_), viewport_);
}

GtkWidget* MainWindow::createMenu() {
    menu_ = gtk_menu_new();
    
    GtkWidget* newTab = gtk_menu_item_new_with_label("New Tab");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_), newTab);
    
    GtkWidget* newWin = gtk_menu_item_new_with_label("New Window");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_), newWin);
    
    GtkWidget* closeTab = gtk_menu_item_new_with_label("Close Tab");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_), closeTab);
    
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_), gtk_separator_menu_item_new());
    
    GtkWidget* about = gtk_menu_item_new_with_label("About");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_), about);
    
    GtkWidget* focus = gtk_menu_item_new_with_label(
        "Focus Mode (Ctrl+Shift+F)");
    g_signal_connect(focus, "activate",
                     G_CALLBACK(on_focus_mode_activate), this);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_), focus);

    // Full-web mode: opens the address-bar URL in the platform web engine
    // (WKWebView / WebKitGTK) behind Lethe policy. Ctrl+Shift+W.
    GtkWidget* fullweb =
        gtk_menu_item_new_with_label("Open in Full Web (Ctrl+Shift+W)");
    g_signal_connect(fullweb, "activate",
                     G_CALLBACK(on_fullweb_activate), this);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_), fullweb);

    GtkWidget* quit = gtk_menu_item_new_with_label("Quit");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_), quit);
    
    return menu_;
}

void MainWindow::triggerFullWeb() {
    if (fullWebCallback_) fullWebCallback_(entryText());
}

void MainWindow::connectSignals() {
    g_signal_connect(window_, "destroy", G_CALLBACK(on_window_destroy), nullptr);
    g_signal_connect(entry_, "activate", G_CALLBACK(on_entry_activate), this);
}

void MainWindow::show() {
    if (window_) {
        gtk_widget_show_all(window_);
    }
}

void MainWindow::run() {
    gtk_main();
}

void MainWindow::quit() {
    gtk_main_quit();
}

} // namespace lethe
