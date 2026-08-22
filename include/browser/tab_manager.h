#ifndef LETHE_BROWSER_TAB_MANAGER_H
#define LETHE_BROWSER_TAB_MANAGER_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "browser/navigation_history.h"

namespace lethe {

struct TabInfo {
    int id;
    std::string title;
    std::string url;
    bool isIncognito;
    bool isLoading;
    
    TabInfo() : id(0), isIncognito(true), isLoading(false) {}
    TabInfo(int tabId) : id(tabId), isIncognito(true), isLoading(false) {}
};

class TabManager {
public:
    TabManager();
    
    int createTab(const std::string& title = "New Tab", const std::string& url = "");
    
    void navigate(int tabId, const std::string& url);
    
    void setActiveTab(int id);
    
    void closeTab(int id);
    
    int getActiveTab() const;
    
    size_t count() const;
    
    const std::vector<int> getAllTabIds() const;
    
    const TabInfo* getTabInfo(int tabId) const;
    
    void setTabLoading(int tabId, bool loading);

    // Publish the loaded page title (from the fetched document).
    void setTabTitle(int tabId, const std::string& title);

    // Publish the final URL after redirects (without re-triggering a load).
    void setTabUrl(int tabId, const std::string& url);

    // Per-tab session history. Each tab records and traverses its own
    // back/forward path; nullptr for unknown tabs.
    NavigationHistory* history(int tabId);

    void closeAllTabs();

private:
    std::map<int, std::unique_ptr<TabInfo>> tabs_;
    std::map<int, std::unique_ptr<NavigationHistory>> tabHistories_;
    int activeTabId = 0;
    int next_id = 1;
};

} // namespace lethe

#endif // LETHE_BROWSER_TAB_MANAGER_H