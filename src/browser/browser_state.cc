// browser_state.cc — Tab and window state management
#include <iostream>
#include "browser/state.h"

namespace lethe {

BrowserState::BrowserState() {
    // Start with one blank tab by default
    addTab();
}

void BrowserState::addTab() {
    int id = tabs.size() + 1;
    Tab t;
    t.id = id;
    t.title = "New Tab";
    t.url = "";
    t.isIncognito = true; // Default incognito mode
    
    tabs.push_back(std::move(t));
    
    if (!activeTabId) {
        activeTabId = id;
    }
}

void BrowserState::navigate(int tabId, const std::string& url) {
    for (auto& t : tabs) {
        if (t->id == tabId) {
            t->url = url;
            std::cout << "[lethe] Tab " << tabId << " -> " << url << "\n";
        }
    }
}

void BrowserState::setActiveTab(int id) {
    for (const auto& t : tabs) {
        if (t->id == id) {
            activeTabId = id;
            return;
        }
    }
    std::cerr << "[lethe] Warning: tab " << id << " not found\n";
}

void BrowserState::closeTab(int id) {
    bool removed = false;
    for (auto it = tabs.begin(); it != tabs.end(); ++it) {
        if (it->id == id) {
            tabs.erase(it);
            removed = true;
            
            if (activeTabId == id) {
                activeTabId = (tabs.size() > 0) ? tabs.front().id : nullptr;
            }
        }
    }
    
    if (!removed) {
        std::cerr << "[lethe] Warning: tab " << id << " not found\n";
    }
}

} // namespace lethe
