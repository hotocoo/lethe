// threat_report.h - shared verdict type for Lethe's built-in scanners
//
// Both the download scanner and the site-reputation checker answer with the
// same shape: a severity, a score, and the individual findings that produced
// it. Keeping the evidence attached is deliberate. A browser that says only
// "this file is dangerous" teaches the user to click through; one that says
// "the name ends in .pdf.app and the payload is a Mach-O executable" lets
// them judge, and lets us debug a false positive without re-running a scan.

#ifndef LETHE_SECURITY_THREAT_REPORT_H
#define LETHE_SECURITY_THREAT_REPORT_H

#include <string>
#include <vector>

namespace lethe {

enum class ThreatSeverity {
    Clean = 0,    // nothing of note
    Notice,       // worth recording, never worth a prompt
    Suspicious,   // warn before opening / before navigating
    Dangerous,    // block by default, allow an explicit override
    Malicious,    // known-bad signature: block, no one-click override
};

// One reason contributing to the verdict.
struct ThreatFinding {
    std::string id;        // stable identifier, e.g. "file.double_extension"
    std::string detail;    // human-readable evidence
    ThreatSeverity severity = ThreatSeverity::Notice;
    int score = 0;         // contribution to the aggregate score
};

struct ThreatReport {
    ThreatSeverity severity = ThreatSeverity::Clean;
    int score = 0;                          // 0-100, saturating
    std::string subject;                    // file path or URL scanned
    std::string identifiedType;             // sniffed format, when known
    std::vector<ThreatFinding> findings;

    bool clean() const { return severity == ThreatSeverity::Clean; }
    // Should the shell refuse the action unless the user overrides?
    bool blocked() const {
        return severity == ThreatSeverity::Dangerous ||
               severity == ThreatSeverity::Malicious;
    }
    // One-line summary for logs and UI.
    std::string summary() const;
};

const char* threatSeverityName(ThreatSeverity severity);

// Adds \p finding and recomputes severity/score. Severity is the maximum of
// the findings' severities; the score saturates at 100 so a file with many
// small oddities can reach a warning without any single rule claiming
// certainty it does not have.
void addFinding(ThreatReport& report, ThreatFinding finding);

}  // namespace lethe

#endif  // LETHE_SECURITY_THREAT_REPORT_H
