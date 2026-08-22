#include "address_bar.h"
#include <iostream>

namespace lethe {

// Namespace-scope (not static) so it matches the friend declaration in
// AddressBar and can reach private members through the passed pointer.
// Namespace-scope (not static) so it matches the friend declaration in
// AddressBar and can reach private members through the passed pointer.
void onAddressBarActivate(GtkWidget* widget, gpointer data) {
    (void)widget;
    AddressBar* self = static_cast<AddressBar*>(data);
    std::string text = self->getText();
    if (!text.empty() && self->navigateCallback_) {
        self->navigateCallback_(text);
    }
}

AddressBar::AddressBar() : entry_(nullptr), loadingSpinner_(nullptr) {
}

AddressBar::~AddressBar() {
}

GtkWidget* AddressBar::create() {
    entry_ = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_), "Enter URL or search...");
    gtk_widget_set_hexpand(entry_, TRUE);
    gtk_widget_set_hexpand_set(entry_, TRUE);
    
    loadingSpinner_ = gtk_spinner_new();
    gtk_widget_set_visible(loadingSpinner_, FALSE);
    
    g_signal_connect(entry_, "activate", G_CALLBACK(onAddressBarActivate), this);
    
    return entry_;
}

void AddressBar::setText(const std::string& text) {
    if (entry_) {
        gtk_entry_set_text(GTK_ENTRY(entry_), text.c_str());
    }
}

std::string AddressBar::getText() const {
    if (entry_) {
        return std::string(gtk_entry_get_text(GTK_ENTRY(entry_)));
    }
    return {};
}

void AddressBar::setPlaceholder(const std::string& placeholder) {
    if (entry_) {
        gtk_entry_set_placeholder_text(GTK_ENTRY(entry_), placeholder.c_str());
    }
}

void AddressBar::setNavigateCallback(NavigateCallback callback) {
    navigateCallback_ = callback;
}

void AddressBar::showLoading(bool loading) {
    if (loadingSpinner_) {
        gtk_widget_set_visible(loadingSpinner_, loading);
        if (loading) {
            gtk_spinner_start(GTK_SPINNER(loadingSpinner_));
        } else {
            gtk_spinner_stop(GTK_SPINNER(loadingSpinner_));
        }
    }
}

} // namespace lethe
