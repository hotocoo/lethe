// tab_manager.cc - Browser state management implementation
#include <iostream>
#include <vector>
#include "browser/tab_manager.h"

namespace lethe {

TabManager::TabManager() {
    int id = createTab("New Tab", "");
    if (id > 0) activeTabId = id;
}

int TabManager::createTab(const std::string& title, const std::string& url) {
    int id = next_id++;
    
    tabs_[id] = std::make_unique<TabInfo>(id);
    tabs_[id]->title = title;
    tabs_[id]->url = url;
    tabs_[id]->isIncognito = true;
    tabs_[id]->isLoading = false;
    
    return id;
}

void TabManager::navigate(int tabId, const std::string& url) {
    auto it = tabs_.find(tabId);
    if (it != tabs_.end()) {
        it->second->url = url;
        it->second->isLoading = true;
        std::cout << "[lethe] Tab " << tabId << " navigating to " << url << std::endl;
    } else {
        std::cerr << "[lethe] Warning: tab " << tabId << " not found" << std::endl;
    }
}

void TabManager::setActiveTab(int id) {
    auto it = tabs_.find(id);
    if (it != tabs_.end()) {
        activeTabId = id;
    } else {
        std::cerr << "[lethe] Warning: tab " << id << " not found" << std::endl;
    }
}

void TabManager::closeTab(int tabId) {
    auto it = tabs_.find(tabId);
    if (it != tabs_.end()) {
        tabs_.erase(it);
        
        if (activeTabId == tabId && !tabs_.empty()) {
            activeTabId = tabs_.begin()->first;
        }
    } else {
        std::cerr << "[lethe] Warning: tab " << tabId << " not found" << std::endl;
    }
}

int TabManager::getActiveTab() const {
    return activeTabId;
}

size_t TabManager::count() const {
    return tabs_.size();
}

const std::vector<int> TabManager::getAllTabIds() const {
    std::vector<int> ids;
    ids.reserve(tabs_.size());
    for (const auto& pair : tabs_) {
        ids.push_back(pair.first);
    }
    return ids;
}

const TabInfo* TabManager::getTabInfo(int tabId) const {
    auto it = tabs_.find(tabId);
    if (it != tabs_.end()) {
        return it->second.get();
    }
    return nullptr;
}

void TabManager::setTabLoading(int tabId, bool loading) {
    auto it = tabs_.find(tabId);
    if (it != tabs_.end()) {
        it->second->isLoading = loading;
    }
}

void TabManager::closeAllTabs() {
    tabs_.clear();
    next_id = 1;
    activeTabId = 0;
}

} // namespace lethe
