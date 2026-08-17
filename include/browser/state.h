#ifndef LETHE_BROWSER_STATE_H
#define LETHE_BROWSER_STATE_H

#include <memory>
#include <string>
#include <vector>

namespace lethe {

struct Tab {
    int id;
    std::string title;
    std::string url;
    bool isIncognito;
};

class BrowserState {
public:
    BrowserState();

    // Create new tab and set as active
    void addTab();

    // Navigate specific tab to URL
    void navigate(int tabId, const std::string& url);

    // Set which tab is active
    void setActiveTab(int id);

    // Close tab by ID
    void closeTab(int id);

    // Get number of open tabs
    size_t getTabCount() const { return tabs.size(); }

private:
    std::vector<std::unique_ptr<Tab>> tabs;
    int activeTabId = 0;
};

} // namespace lethe

#endif // LETHE_BROWSER_STATE_H
