// tab_manager.cc - Browser state management implementation
#include <iostream>
#include "browser/tab_manager.h"

namespace lethe {

TabManager::TabManager() {
    // Start with a single blank tab by default
    int id = createTab();
    
    if (!activeTabId) activeTabId = id;
}

int TabManager::createTab(const std::string& title, const std::string& url) {
    int id = next_id++;
    
    tabs_[id] = std::make_unique<TabInfo>(id);
    tabs_[id]->title = title;
    tabs_[id]->url = url;
    tabs_[id]->isIncognito = true; // Default to incognito mode
    
    return id;
}

void TabManager::closeTab(int tabId) {
    if (tabs_.count(tabId)) {
        tabs_.erase(tabId);
        
        if (activeTabId == tabId && !tabs_.empty()) {
            activeTabId = tabs_.begin()->first;
        }
    } else {
        std::cerr << "[lethe] Warning: tab " << tabId << " not found\n";
    }
}

void TabManager::navigate(int tabId, const std::string& url) {
    if (tabs_.count(tabId)) {
        tabs_[tabId]->url = url;
        std::cout << "[lethe] Tab " << tabId << " -> " << url << "\n";
    } else {
        std::cerr << "[lethe] Warning: tab " << tabId << " not found\n";
    }
}

void TabManager::setActiveTab(int id) {
    if (tabs_.count(id)) {
        activeTabId = id;
    } else {
        std::cerr << "[lethe] Warning: tab " << id << " not found\n";
    }
}

int TabManager::getActiveTab() const { return activeTabId; }

size_t TabManager::count() const { return tabs_.size(); }

void TabManager::closeAllTabs() {
    tabs_.clear();
    next_id = 1;
    activeTabId = 0;
}

} // namespace lethe
