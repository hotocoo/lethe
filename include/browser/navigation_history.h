#ifndef LETHE_BROWSER_NAVIGATION_HISTORY_H
#define LETHE_BROWSER_NAVIGATION_HISTORY_H

#include <vector>
#include <string>
#include <ctime>

namespace lethe {

struct HistoryEntry {
    std::string url;
    std::string title;
    time_t timestamp;
    
    HistoryEntry(const std::string& u, const std::string& t) 
        : url(u), title(t), timestamp(time(nullptr)) {}
};

class NavigationHistory {
public:
    void addEntry(const std::string& url, const std::string& title = "") {
        if (entries_.size() >= MAX_ENTRIES) {
            entries_.erase(entries_.begin());
        }
        entries_.emplace_back(url, title);
    }

    size_t size() const { return entries_.size(); }

    bool empty() const { return entries_.empty(); }

    void clear() { entries_.clear(); }

private:
    std::vector<HistoryEntry> entries_;
    static constexpr size_t MAX_ENTRIES = 1000;
};

} // namespace lethe

#endif // LETHE_BROWSER_NAVIGATION_HISTORY_H