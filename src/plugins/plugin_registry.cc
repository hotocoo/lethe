// plugin_registry.cc - see include/plugins/plugin_registry.h

#include "plugins/plugin_registry.h"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "browser/shell_context.h"

namespace lethe {

namespace {

using ApplyFn = std::function<void(ShellContext&, bool)>;

// Minimal, dependency-free JSON for the overrides file. The format is ours
// (one flat array of {id, enabled}); ids are [a-z0-9-] by construction -
// still, quote defensively.
std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

// Reads {"plugins":[{"id":"x","enabled":true}, ...]} without pulling in a
// JSON library. Tolerant: malformed entries and unknown ids are skipped,
// parsing stops at the array's closing bracket.
void parseOverrides(const std::string& json, std::map<std::string, bool>* out) {
    size_t i = json.find("\"plugins\"");
    if (i == std::string::npos) return;
    i = json.find('[', i);
    if (i == std::string::npos) return;
    ++i;
    while (i < json.size()) {
        // Skip whitespace and commas between objects.
        while (i < json.size() && (json[i] == ' ' || json[i] == ',' ||
                                   json[i] == '\n' || json[i] == '\t' ||
                                   json[i] == '\r')) {
            ++i;
        }
        if (i >= json.size() || json[i] == ']') return;
        if (json[i] != '{') return;
        const size_t end = json.find('}', i);
        if (end == std::string::npos) return;
        const std::string obj = json.substr(i, end - i);
        i = end + 1;
        const size_t idPos = obj.find("\"id\"");
        const size_t enPos = obj.find("\"enabled\"");
        if (idPos == std::string::npos || enPos == std::string::npos) continue;
        const size_t idq1 = obj.find('"', idPos + 4);
        if (idq1 == std::string::npos) continue;
        const size_t idq2 = obj.find('"', idq1 + 1);
        if (idq2 == std::string::npos) continue;
        const std::string id = obj.substr(idq1 + 1, idq2 - idq1 - 1);
        // Search for the value only after the key's colon - "enabled"
        // itself contains an 'n', which would otherwise read as false.
        const size_t colon = obj.find(':', enPos);
        if (colon == std::string::npos) continue;
        const size_t vPos = obj.find_first_of("tfn", colon + 1);
        if (vPos == std::string::npos) continue;
        const bool on = obj[vPos] == 't';
        if (!id.empty()) (*out)[id] = on;
    }
}

PluginSpec privacy(const char* id, const char* name, const char* desc,
                   bool defaultOn, const char* prefKey,
                   ApplyFn apply = nullptr) {
    PluginSpec p;
    p.id = id; p.name = name; p.description = desc; p.group = "privacy";
    p.defaultOn = defaultOn; p.prefKey = prefKey; p.apply = std::move(apply);
    return p;
}

} // namespace

PluginRegistry& PluginRegistry::instance() {
    static PluginRegistry r;
    return r;
}

void PluginRegistry::add(PluginSpec spec) {
    // One spec per id: a second registration of the same id replaces the
    // first (keeps registerBuiltins idempotent and lets tests override).
    auto it = std::find_if(plugins_.begin(), plugins_.end(),
                           [&](const PluginSpec& p) { return p.id == spec.id; });
    if (it != plugins_.end()) *it = std::move(spec);
    else plugins_.push_back(std::move(spec));
}

void PluginRegistry::registerBuiltins() {
    using P = PluginSpec;
    // ---- Privacy ---------------------------------------------------------
    {
        P p = privacy("tracker-block", "Tracker protection",
            "Block known third-party advertising, analytics and identity "
            "hosts before their requests leave the engine.",
            true, "trackerBlocking",
            [](ShellContext& ctx, bool on) { ctx.trackerBlocking = on; });
        add(std::move(p));
    }
    {
        P p = privacy("https-first", "HTTPS-first",
            "Try the https:// form of every top-level http:// address first; "
            "fall back only with an explicit, labelled link.",
            true, "httpsFirst",
            [](ShellContext& ctx, bool on) { ctx.httpsFirst = on; });
        add(std::move(p));
    }
    add(privacy("https-only", "HTTPS-only",
        "Refuse plain http:// addresses outright. No upgrade, no fallback.",
        false, "httpsOnly"));
    add(privacy("stealth-ua", "Stealth user agent",
        "Send one fixed, low-entropy User-Agent profile on every request "
        "instead of the platform default.", false, "stealthUA",
        [](ShellContext& ctx, bool on) {
            ctx.cfg.userAgentMode = on ? "stealth" : "standard";
        }));
    add(privacy("do-not-track", "Do Not Track",
        "Send DNT=1 on every request.", true, "doNotTrack"));
    add(privacy("fingerprint-shield", "Fingerprint shield",
        "Reduce canvas, font and audio-context entropy available to "
        "fingerprinters.", true, "blockFingerprinting"));
    add(privacy("third-party-cookie-block", "Third-party cookie block",
        "Reject cookies set by origins other than the one in the address "
        "bar.", true, "blockThirdPartyCookies"));
    add(privacy("referer-strip", "Referer strip",
        "Strip the Referer header on cross-origin navigations.", true,
        "blockReferer"));
    add(privacy("webrtc-block", "WebRTC block",
        "Block WebRTC, which can leak local and VPN-internal addresses.",
        true, "blockWebRTC"));
    {
        P p = privacy("oblivion-windows", "Oblivion windows",
            "Private windows with an isolated in-memory site-data store wiped "
            "when the last tab closes, https-only, forced tracker protection "
            "and stealth UA.", true, "");
        p.group = "privacy";
        // Engine-only: persisted through the overrides JSON, consumed by the
        // shell menus (the "New Oblivion Window" item validates against it).
        add(std::move(p));
    }

    // ---- Data ------------------------------------------------------------
    {
        P p;
        p.id = "persistent-cookies"; p.name = "Persistent site data";
        p.description = "Keep cookies and site data between launches. Off, "
                        "Lethe is ephemeral (incognito by default).";
        p.group = "data"; p.defaultOn = false; p.prefKey = "persistentCookies";
        p.requiresRestart = true;  // data store is fixed per data store object
        add(std::move(p));
    }

    // ---- Network ---------------------------------------------------------
    {
        P p;
        p.id = "secure-dns"; p.name = "Secure DNS (DoH)";
        p.description = "Resolve every name through DNS-over-HTTPS; plain "
                        "UDP DNS never happens.";
        p.group = "network"; p.defaultOn = true; p.prefKey = "";
        p.requiresRestart = true;  // proxy + gate hold the provider at start
        add(std::move(p));
    }
    {
        P p;
        p.id = "doh-cache"; p.name = "DoH shared cache";
        p.description = "One answer cache shared by the gate, reader mode "
                        "and the policy proxy.";
        p.group = "network"; p.defaultOn = true; p.prefKey = "dohSharedCache";
        p.requiresRestart = true;
        add(std::move(p));
    }
    {
        P p;
        p.id = "doh-pool"; p.name = "DoH keep-alive pool";
        p.description = "Keep TLS connections to the DNS provider warm and "
                        "reuse them across lookups.";
        p.group = "network"; p.defaultOn = true; p.prefKey = "dohPool";
        p.requiresRestart = true;
        add(std::move(p));
    }
    {
        P p;
        p.id = "policy-proxy"; p.name = "Policy proxy (transport enforcement)";
        p.description = "Route all engine traffic through the local "
                        "authenticated policy proxy so subresources are "
                        "policy-checked at the transport layer.";
        p.group = "network"; p.defaultOn = true; p.prefKey = "policyProxy";
        p.requiresRestart = true;
        add(std::move(p));
    }
    {
        P p;
        p.id = "private-net-isolation"; p.name = "Private-network isolation";
        p.description = "Refuse requests that resolve to private, loopback or "
                        "link-local ranges (SSRF guard).";
        p.group = "network"; p.defaultOn = true;
        p.prefKey = "isolatePrivateNetworks"; p.requiresRestart = true;
        add(std::move(p));
    }
    {
        P p;
        p.id = "vpn"; p.name = "Built-in VPN";
        p.description = "Route policy-proxy traffic through Lethe's "
                        "WireGuard-style tunnel (fail-closed loopback until "
                        "an endpoint is configured).";
        p.group = "network"; p.defaultOn = true; p.prefKey = "";
        p.apply = [](ShellContext& ctx, bool on) {
            if (!ctx.engine) return;
            if (on) {
                if (!ctx.engine->isVpnConnected()) ctx.engine->enableVpn(ctx.cfg.vpnConfig);
            } else {
                ctx.engine->disableVpn();
            }
        };
        add(std::move(p));
    }

    // ---- Engine ----------------------------------------------------------
    {
        P p;
        p.id = "javascript"; p.name = "JavaScript";
        p.description = "Run JavaScript in pages. Off breaks most modern "
                        "sites; use for untrusted content.";
        p.group = "engine"; p.defaultOn = true; p.prefKey = "javaScript";
        add(std::move(p));
    }
    {
        P p;
        p.id = "hardware-accel"; p.name = "Hardware acceleration";
        p.description = "Composite on the GPU. Off forces software rendering "
                        "(debugging aid, large performance cost).";
        p.group = "engine"; p.defaultOn = true;
        p.prefKey = "hardwareAcceleration"; p.requiresRestart = true;
        add(std::move(p));
    }

    // ---- Performance -----------------------------------------------------
    {
        P p;
        p.id = "high-refresh"; p.name = "High refresh rate";
        p.description = "Schedule animation frames against the display's "
                        "native rate (90/120/144 Hz) instead of the "
                        "conservative 60 Hz tier.";
        p.group = "performance"; p.defaultOn = true;
        p.prefKey = "preferHighRefresh";
        add(std::move(p));
    }

    // ---- Privacy of Lethe itself ------------------------------------------
    {
        P p;
        p.id = "telemetry"; p.name = "Telemetry";
        p.description = "Send anonymous usage pings. Off by default; Lethe "
                        "does not phone home.";
        p.group = "privacy"; p.defaultOn = false; p.prefKey = "telemetry";
        add(std::move(p));
    }
    {
        P p;
        p.id = "crash-reports"; p.name = "Crash reports";
        p.description = "Send stack traces after a crash. Off by default.";
        p.group = "privacy"; p.defaultOn = false; p.prefKey = "crashReports";
        add(std::move(p));
    }
}

const PluginSpec* PluginRegistry::find(const std::string& id) const {
    auto it = std::find_if(plugins_.begin(), plugins_.end(),
                           [&](const PluginSpec& p) { return p.id == id; });
    return it == plugins_.end() ? nullptr : &*it;
}

bool PluginRegistry::enabled(const std::string& id) const {
    auto o = overrides_.find(id);
    if (o != overrides_.end()) return o->second;
    const PluginSpec* p = find(id);
    return p ? p->defaultOn : false;
}

void PluginRegistry::setEnabled(const std::string& id, bool on) {
    overrides_[id] = on;
}

bool PluginRegistry::hasOverride(const std::string& id) const {
    return overrides_.count(id) != 0;
}

void PluginRegistry::clearOverride(const std::string& id) {
    overrides_.erase(id);
}

std::string PluginRegistry::toJson() const {
    std::ostringstream o;
    o << "{\"plugins\":[";
    bool first = true;
    for (const auto& kv : overrides_) {
        if (!first) o << ",";
        first = false;
        o << "{\"id\":\"" << jsonEscape(kv.first)
          << "\",\"enabled\":" << (kv.second ? "true" : "false") << "}";
    }
    o << "]}";
    return o.str();
}

void PluginRegistry::loadOverridesJson(const std::string& json) {
    std::map<std::string, bool> parsed;
    parseOverrides(json, &parsed);
    for (const auto& kv : parsed) {
        if (find(kv.first)) overrides_[kv.first] = kv.second;
    }
}

void PluginRegistry::applyTo(ShellContext& ctx) const {
    for (const auto& p : plugins_) {
        if (!p.apply) continue;
        auto o = overrides_.find(p.id);
        if (o == overrides_.end()) continue;
        p.apply(ctx, o->second);
    }
}

} // namespace lethe
