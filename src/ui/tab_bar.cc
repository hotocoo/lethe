#include "tab_bar.h"
#include <iostream>
#include <algorithm>

namespace lethe {

namespace {

// The tab id rides on the tab widget as object data, so the C-style GTK
// callbacks need no per-widget heap allocation.
const char kTabIdKey[] = "lethe-tab-id";

int widgetTabId(GtkWidget* widget) {
    return GPOINTER_TO_INT(g_object_get_data(G_OBJECT(widget), kTabIdKey));
}

} // namespace

// Namespace-scope (not static) so they match the friend declarations in
// TabBar and can reach private members through the passed pointer.

void onTabButtonPressed(GtkWidget* widget, GdkEventButton* event,
                        gpointer data) {
    (void)event;
    auto* self = static_cast<TabBar*>(data);
    const int tabId = widgetTabId(widget);
    if (self->engine_ && self->engine_->tabManager()) {
        self->engine_->tabManager()->setActiveTab(tabId);
        self->setActiveTab(tabId);
    }
    if (self->tabSelectCallback_) {
        self->tabSelectCallback_(tabId);
    }
}

void onTabCloseClicked(GtkWidget* widget, gpointer data) {
    auto* self = static_cast<TabBar*>(data);
    // The clicked widget is the close button; the tab id lives on the
    // parent tab box (fall back to the button itself if unparented).
    GtkWidget* tabBox = gtk_widget_get_parent(widget);
    const int tabId = tabBox ? widgetTabId(tabBox) : widgetTabId(widget);
    if (self->tabCloseCallback_) {
        self->tabCloseCallback_(tabId);
    }
}

void onNewTabClicked(GtkWidget* widget, gpointer data) {
    (void)widget;
    auto* self = static_cast<TabBar*>(data);
    if (self->engine_ && self->engine_->tabManager()) {
        int newTabId = self->engine_->tabManager()->createTab("New Tab", "");
        self->updateTabs();
        self->setActiveTab(newTabId);
    }
}

TabBar::TabBar(Engine* engine) : engine_(engine), box_(nullptr), newTabButton_(nullptr) {
}

TabBar::~TabBar() {
}

GtkWidget* TabBar::create() {
    box_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_set_border_width(GTK_CONTAINER(box_), 2);

    addNewTabButton();
    updateTabs();

    return box_;
}

void TabBar::updateTabs() {
    if (!engine_ || !engine_->tabManager() || !box_) return;

    // Clear existing tab widgets.
    for (auto& pair : tabWidgets_) {
        gtk_container_remove(GTK_CONTAINER(box_), pair.second);
    }
    tabWidgets_.clear();

    // Recreate widgets for every tab the engine knows about.
    std::vector<int> tabIds = engine_->tabManager()->getAllTabIds();
    for (int tabId : tabIds) {
        createTabWidget(tabId);
    }

    int activeTab = engine_->tabManager()->getActiveTab();
    if (tabWidgets_.find(activeTab) != tabWidgets_.end()) {
        setActiveTab(activeTab);
    }
}

void TabBar::createTabWidget(int tabId) {
    if (!engine_ || !engine_->tabManager()) return;

    const TabInfo* info = engine_->tabManager()->getTabInfo(tabId);
    if (!info) return;

    GtkWidget* tabBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_set_border_width(GTK_CONTAINER(tabBox), 2);
    g_object_set_data(G_OBJECT(tabBox), kTabIdKey, GINT_TO_POINTER(tabId));

    // Tab label.
    GtkWidget* label = gtk_label_new(info->title.c_str());
    gtk_widget_set_margin_start(label, 6);
    gtk_widget_set_margin_end(label, 2);
    gtk_box_pack_start(GTK_BOX(tabBox), label, TRUE, TRUE, 0);

    // Close button (themed icon: stock IDs are deprecated and GTK4-gone).
    GtkWidget* closeButton =
        gtk_button_new_from_icon_name("window-close", GTK_ICON_SIZE_MENU);
    gtk_button_set_relief(GTK_BUTTON(closeButton), GTK_RELIEF_NONE);
    gtk_widget_set_size_request(closeButton, 16, 16);
    gtk_box_pack_start(GTK_BOX(tabBox), closeButton, FALSE, FALSE, 0);

    g_signal_connect(tabBox, "button-press-event",
                     G_CALLBACK(onTabButtonPressed), this);
    g_signal_connect(closeButton, "clicked",
                     G_CALLBACK(onTabCloseClicked), this);

    // Append, then reorder so tabs stay before the trailing "+" button.
    gtk_box_pack_start(GTK_BOX(box_), tabBox, FALSE, FALSE, 0);
    gtk_box_reorder_child(GTK_BOX(box_), tabBox,
                          static_cast<gint>(tabWidgets_.size()));
    tabWidgets_[tabId] = tabBox;
}

void TabBar::removeTabWidget(int tabId) {
    auto it = tabWidgets_.find(tabId);
    if (it != tabWidgets_.end()) {
        gtk_container_remove(GTK_CONTAINER(box_), it->second);
        tabWidgets_.erase(it);
    }
}

void TabBar::setActiveTab(int tabId) {
    for (auto& pair : tabWidgets_) {
        const bool isActive = (pair.first == tabId);
        gtk_widget_set_name(pair.second, isActive ? "active-tab" : "tab");
    }
}

void TabBar::addNewTabButton() {
    newTabButton_ =
        gtk_button_new_from_icon_name("list-add", GTK_ICON_SIZE_MENU);
    gtk_button_set_relief(GTK_BUTTON(newTabButton_), GTK_RELIEF_NONE);
    gtk_widget_set_size_request(newTabButton_, 24, 24);
    gtk_box_pack_start(GTK_BOX(box_), newTabButton_, FALSE, FALSE, 0);

    g_signal_connect(newTabButton_, "clicked",
                     G_CALLBACK(onNewTabClicked), this);
}

void TabBar::setTabCloseCallback(TabCloseCallback callback) {
    tabCloseCallback_ = callback;
}

void TabBar::setTabSelectCallback(TabSelectCallback callback) {
    tabSelectCallback_ = callback;
}

} // namespace lethe
