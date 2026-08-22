#ifndef LETHE_UI_TAB_BAR_H
#define LETHE_UI_TAB_BAR_H

#include <gtk/gtk.h>
#include <map>
#include <string>
#include <vector>
#include <functional>
#include "core/engine.h"

namespace lethe {

class TabBar {
public:
    using TabCloseCallback = std::function<void(int)>;
    using TabSelectCallback = std::function<void(int)>;
    
    TabBar(Engine* engine);
    ~TabBar();
    
    GtkWidget* create();
    void updateTabs();
    void setActiveTab(int tabId);
    void addNewTabButton();
    
    void setTabCloseCallback(TabCloseCallback callback);
    void setTabSelectCallback(TabSelectCallback callback);
    
    GtkWidget* getWidget() { return box_; }

private:
    // GTK callbacks are C function pointers: the handlers live at namespace
    // scope and reach private state as friends (see tab_bar.cc).
    friend void onTabButtonPressed(GtkWidget* widget, GdkEventButton* event,
                                   gpointer data);
    friend void onTabCloseClicked(GtkWidget* widget, gpointer data);
    friend void onNewTabClicked(GtkWidget* widget, gpointer data);

    void createTabWidget(int tabId);
    void removeTabWidget(int tabId);
    
    Engine* engine_;
    GtkWidget* box_;
    GtkWidget* newTabButton_;
    std::map<int, GtkWidget*> tabWidgets_;
    TabCloseCallback tabCloseCallback_;
    TabSelectCallback tabSelectCallback_;
};

} // namespace lethe

#endif // LETHE_UI_TAB_BAR_H
