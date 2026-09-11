// threat_report.cc - see include/security/threat_report.h

#include "security/threat_report.h"

#include <algorithm>

namespace lethe {

const char* threatSeverityName(ThreatSeverity severity) {
    switch (severity) {
        case ThreatSeverity::Clean: return "clean";
        case ThreatSeverity::Notice: return "notice";
        case ThreatSeverity::Suspicious: return "suspicious";
        case ThreatSeverity::Dangerous: return "dangerous";
        case ThreatSeverity::Malicious: return "malicious";
    }
    return "unknown";
}

void addFinding(ThreatReport& report, ThreatFinding finding) {
    if (static_cast<int>(finding.severity) > static_cast<int>(report.severity))
        report.severity = finding.severity;
    report.score = std::min(100, report.score + std::max(0, finding.score));
    report.findings.push_back(std::move(finding));
}

std::string ThreatReport::summary() const {
    std::string out = std::string(threatSeverityName(severity)) + " (score " +
                      std::to_string(score) + ")";
    if (!identifiedType.empty()) out += " " + identifiedType;
    if (!findings.empty()) {
        out += ": " + findings.front().detail;
        if (findings.size() > 1)
            out += " (+" + std::to_string(findings.size() - 1) + " more)";
    }
    return out;
}

}  // namespace lethe
