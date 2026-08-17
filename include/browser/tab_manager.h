#ifndef LETHE_BROWSER_TAB_MANAGER_H
#define LETHE_BROWSER_TAB_MANAGER_H

#include <vector>
#include <memory>
#include <string>
#include <map>

namespace lethe {

struct TabInfo {
    int id;
    std::string title;
    std::string url;
    bool isIncognito;
    
    TabInfo(int i, const std::string& t, const std::string& u) : id(i), title(t), url(u), isIncognito(true) {}
};

class TabManager {
public:
    int createTab(const std::string& title = "New Tab", const std::string& url = "") {
        int id = nextId_++;
        tabs_.emplace(id, std::make_unique<TabInfo>(id, title, url)));
        
        if (!activeTab_) activeTab_ = id;
        
        return id;
    }

    void closeTab(int tabId) {
        tabs_.erase(tabId);
        
        if (activeTab_ == tabId && !tabs_.empty()) {
            activeTab_ = tabs_.begin()->first;
        }
    }

    void setActiveTab(int tabId) {
        if (tabs_.count(tabId)) {
            activeTab_ = tabId;
        }
    }

    int getActiveTab() const { return activeTab_; }

    size_t count() const { return tabs_.size(); }

private:
    std::map<int, std::unique_ptr<TabInfo>> tabs_;
    int activeTab_ = 0;
    int nextId_ = 1;
};

} // namespace lethe

#endif // LETHE_BROWSER_TAB_MANAGER_H
