#ifndef LETHE_UI_ADDRESS_BAR_H
#define LETHE_UI_ADDRESS_BAR_H

#include <gtk/gtk.h>
#include <string>
#include <functional>

namespace lethe {

class AddressBar {
public:
    using NavigateCallback = std::function<void(const std::string&)>;
    
    AddressBar();
    ~AddressBar();
    
    GtkWidget* create();
    void setText(const std::string& text);
    std::string getText() const;
    void setPlaceholder(const std::string& placeholder);
    void setNavigateCallback(NavigateCallback callback);
    void showLoading(bool loading);
    
    GtkWidget* getWidget() { return entry_; }

private:
    friend void onAddressBarActivate(GtkWidget* widget, gpointer data);
    
    GtkWidget* entry_;
    GtkWidget* loadingSpinner_;
    NavigateCallback navigateCallback_;
};

} // namespace lethe

#endif // LETHE_UI_ADDRESS_BAR_H
