#ifndef LETHE_BROWSER_TAB_MANAGER_H
#define LETHE_BROWSER_TAB_MANAGER_H

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace lethe {

struct TabInfo {
    int id;
    std::string title;
    std::string url;
    bool isIncognito;
    
    TabInfo() : id(0), isIncognito(true) {}
};

class TabManager {
public:
    TabManager();
    
    // Create new tab and set as active
    int createTab(const std::string& title = "New Tab", const std::string& url = "");
    
    // Navigate specific tab to URL
    void navigate(int tabId, const std::string& url);
    
    // Set which tab is active
    void setActiveTab(int id);
    
    // Close tab by ID
    void closeTab(int id);
    
    // Get the currently active tab ID
    int getActiveTab() const { return activeTabId; }
    
    // Get number of open tabs
    size_t count() const { return tabs_.size(); }
    
    // Close all tabs (used on shutdown)
    void closeAllTabs();

private:
    std::map<int, std::unique_ptr<TabInfo>> tabs_;
    int activeTabId = 0;
    int next_id = 1;
};

} // namespace lethe

#endif // LETHE_BROWSER_TAB_MANAGER_H