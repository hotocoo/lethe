#ifndef LETHE_BROWSER_NAVIGATION_HISTORY_H
#define LETHE_BROWSER_NAVIGATION_HISTORY_H

#include <optional>
#include <string>
#include <vector>
#include <ctime>

namespace lethe {

struct HistoryEntry {
    std::string url;
    std::string title;
    time_t timestamp;

    HistoryEntry() : timestamp(0) {}
    HistoryEntry(const std::string& u, const std::string& t) 
        : url(u), title(t), timestamp(time(nullptr)) {}
};

// Session navigation history with browser back/forward semantics:
// a new entry truncates the forward branch, and traversal moves a cursor.
class NavigationHistory {
public:
    // Record a visit: drops any forward branch, appends, cursor at the end.
    void addEntry(const std::string& url, const std::string& title = "") {
        entries_.resize(cursor_ + 1);
        entries_.emplace_back(url, title);
        if (entries_.size() > MAX_ENTRIES) {
            entries_.erase(entries_.begin());
        }
        cursor_ = static_cast<int>(entries_.size()) - 1;
    }

    size_t size() const { return entries_.size(); }

    bool empty() const { return entries_.empty(); }

    void clear() { entries_.clear(); cursor_ = -1; }

    // Recorded entries, oldest first (for OS introspection and UI).
    const std::vector<HistoryEntry>& entries() const { return entries_; }

    // Whether any entry records this exact URL.
    bool containsUrl(const std::string& url) const {
        for (const auto& e : entries_) {
            if (e.url == url) return true;
        }
        return false;
    }

    // --- Back/forward traversal ---
    bool canGoBack() const { return cursor_ > 0; }
    bool canGoForward() const {
        return !entries_.empty() &&
               cursor_ + 1 < static_cast<int>(entries_.size());
    }

    // Peek at where back/forward would go WITHOUT moving the cursor.
    // Returned pointer is valid until the next history mutation.
    const HistoryEntry* peekBack() const {
        return canGoBack() ? &entries_[static_cast<size_t>(cursor_ - 1)]
                           : nullptr;
    }
    const HistoryEntry* peekForward() const {
        return canGoForward() ? &entries_[static_cast<size_t>(cursor_ + 1)]
                              : nullptr;
    }

    // Move the cursor; returns the entry landed on (nullptr at the edge).
    // The pointer is valid until the next history mutation.
    const HistoryEntry* goBack() {
        if (!canGoBack()) return nullptr;
        return &entries_[static_cast<size_t>(--cursor_)];
    }
    const HistoryEntry* goForward() {
        if (!canGoForward()) return nullptr;
        return &entries_[static_cast<size_t>(++cursor_)];
    }

    // The entry the cursor currently sits on (nullptr when empty).
    const HistoryEntry* current() const {
        return empty() ? nullptr
                       : &entries_[static_cast<size_t>(cursor_)];
    }

private:
    std::vector<HistoryEntry> entries_;
    int cursor_ = -1;
    static constexpr size_t MAX_ENTRIES = 1000;
};

} // namespace lethe

#endif // LETHE_BROWSER_NAVIGATION_HISTORY_H
