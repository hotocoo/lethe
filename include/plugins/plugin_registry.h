// plugin_registry.h - every Lethe feature, packaged as a plugin.
//
// The registry is the single structural answer to "turn every feature on
// or off": each capability of the browser registers one PluginSpec here,
// and the shells render their settings surfaces (the macOS Plugins pane,
// lethe://plugins, --list-plugins) straight from this table instead of
// hand-coding per-feature checkboxes.
//
// Two kinds of state live behind a plugin:
//   1. A shell preference key (macOS: LethePreferences JSON). The registry
//      never owns persistence for these - the shell does - it only names
//      the key so UI and manifests can round-trip.
//   2. A runtime apply function, for plugins that can be flipped on a live
//      shell without a relaunch. apply() receives the ShellContext and the
//      new state and does the smallest honest thing: it flips the engine-
//      visible flag. Presentation-level refresh (recompiling tracker rules,
//      pushing the UA to open webViews) stays in the shell's own
//      apply-preferences path, which already exists and already works.
//
// The registry itself persists nothing except an override map held in
// memory; shells load/save it via loadOverridesJson()/toJson() so a shell
// without a native preferences store (lethe-cef, future GTK) can still
// honor user choices from a plain file.
#ifndef LETHE_PLUGINS_PLUGIN_REGISTRY_H
#define LETHE_PLUGINS_PLUGIN_REGISTRY_H

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace lethe {

struct ShellContext;

struct PluginSpec {
    std::string id;        // stable machine id, e.g. "tracker-block"
    std::string name;      // human name, e.g. "Tracker protection"
    std::string description;
    std::string group;     // privacy | network | data | engine | performance
    bool defaultOn = true;
    bool requiresRestart = false;  // live shells cannot apply it mid-session
    // macOS preference key this plugin is persisted under (empty for
    // engine-only plugins, which persist through the overrides JSON).
    std::string prefKey;
    // Live-apply hook. Empty = the shell applies it on its own schedule
    // (next navigation, next webview, or next launch).
    std::function<void(ShellContext&, bool)> apply;
};

class PluginRegistry {
public:
    static PluginRegistry& instance();

    // Registers the full built-in feature set. Idempotent.
    void registerBuiltins();

    void add(PluginSpec spec);
    const std::vector<PluginSpec>& plugins() const { return plugins_; }
    const PluginSpec* find(const std::string& id) const;

    // Current state: user override if set, otherwise the default.
    bool enabled(const std::string& id) const;
    void setEnabled(const std::string& id, bool on);
    bool hasOverride(const std::string& id) const;
    void clearOverride(const std::string& id);

    // {"plugins":[{"id":..., "enabled":true|false}, ...]} - overrides only.
    std::string toJson() const;
    // Tolerant load: unknown ids and malformed entries are ignored; missing
    // ids keep their defaults.
    void loadOverridesJson(const std::string& json);

    // Calls apply(ctx, state) for every plugin that has a live-apply hook
    // and an explicit override. Plugins without a hook are untouched.
    void applyTo(ShellContext& ctx) const;

private:
    PluginRegistry() = default;
    std::vector<PluginSpec> plugins_;
    std::map<std::string, bool> overrides_;
};

} // namespace lethe

#endif // LETHE_PLUGINS_PLUGIN_REGISTRY_H
