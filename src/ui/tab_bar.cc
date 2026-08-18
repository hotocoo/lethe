#include "tab_bar.h"
#include <iostream>
#include <algorithm>

namespace lethe {

TabBar::TabBar(Engine* engine) : engine_(engine), box_(nullptr), newTabButton_(nullptr) {
}

TabBar::~TabBar() {
}

GtkWidget* TabBar::create() {
    box_ = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_set_border_width(GTK_CONTAINER(box_), 2);
    
    // Add new tab button
    addNewTabButton();
    
    // Update tabs from engine
    updateTabs();
    
    return box_;
}

void TabBar::updateTabs() {
    if (!engine_ || !engine_->tabManager()) return;
    
    // Clear existing tab widgets
    for (auto& pair : tabWidgets_) {
        gtk_container_remove(GTK_CONTAINER(box_), pair.second);
    }
    tabWidgets_.clear();
    
    // Create new tab widgets
    std::vector<int> tabIds = engine_->tabManager()->getAllTabIds();
    for (int tabId : tabIds) {
        createTabWidget(tabId);
    }
    
    // Set active tab
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
    gtk_container_set_border_width(GTK_CONTAINER(tabBox_), 2);
    
    // Tab label
    GtkWidget* label = gtk_label_new(info->title.c_str());
    gtk_box_pack_start(GTK_BOX(tabBox), label, TRUE, TRUE, 0);
    
    // Close button
    GtkWidget* closeButton = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
    gtk_button_set_relief(GTK_BUTTON(closeButton_), GTK_RELIEF_NONE);
    gtk_widget_set_size_request(closeButton_, 16, 16);
    gtk_box_pack_start(GTK_BOX(tabBox), closeButton_, FALSE, FALSE, 0);
    
    // Connect signals
    int tabIdCopy = tabId;
    g_signal_connect(tabBox, "button-press-event", 
                     [this, tabIdCopy](GtkWidget* w, GdkEventButton* e, gpointer d) {
                         onTabButtonClicked(tabIdCopy, w, d);
                         return TRUE;
                     }), this);
    
    g_signal_connect(closeButton, "clicked",
                     [this, tabIdCopy](GtkWidget* w, gpointer d) {
                         onTabCloseClicked(tabIdCopy, w, d);
                         return TRUE;
                     }), this);
    
    // Insert before new tab button
    gtk_box_insert(GTK_BOX(box_), tabBox, tabWidgets_.size());
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
        GtkWidget* widget = pair.second;
        bool isActive = (pair.first == tabId);
        // Set active tab style
        gtk_widget_set_name(widget, isActive ? "active-tab" : "tab");
    }
}

void TabBar::addNewTabButton() {
    newTabButton_ = gtk_button_new_from_stock(GTK_STOCK_ADD);
    gtk_button_set_relief(GTK_BUTTON(newTabButton_), GTK_RELIEF_NONE);
    gtk_widget_set_size_request(newTabButton_, 24, 24);
    gtk_box_pack_start(GTK_BOX(box_), newTabButton_, FALSE, FALSE, 0);
    
    g_signal_connect(newTabButton_, "clicked", G_CALLBACK(onNewTabClicked), this);
}

void TabBar::setTabCloseCallback(TabCloseCallback callback) {
    tabCloseCallback_ = callback;
}

void TabBar::setTabSelectCallback(TabSelectCallback callback) {
    tabSelectCallback_ = callback;
}

void TabBar::onTabButtonClicked(int tabId, GtkWidget* widget, gpointer data) {
    TabBar* self = static_cast<TabBar*>(data);
    if (self->engine_ && self->engine_->tabManager()) {
        self->engine_->tabManager()->setActiveTab(tabId);
        self->setActiveTab(tabId);
    }
    if (self->tabSelectCallback_) {
        self->tabSelectCallback_(tabId);
    }
}

void TabBar::onTabCloseClicked(int tabId, GtkWidget* widget, gpointer data) {
    TabBar* self = static_cast<TabBar*>(data);
    if (self->tabCloseCallback_) {
        self->tabCloseCallback_(tabId);
    }
}

void TabBar::onNewTabClicked(GtkWidget* widget, gpointer data) {
    TabBar* self = static_cast<TabBar*>(data);
    if (self->engine_ && self->engine_->tabManager()) {
        int newTabId = self->engine_->tabManager()->createTab("New Tab", "");
        self->updateTabs();
        self->setActiveTab(newTabId);
    }
}

} // namespace lethe
