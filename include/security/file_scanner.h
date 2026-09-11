// file_scanner.h - Lethe's built-in scanner for downloaded files
//
// This is a real static scanner, not a cloud lookup: no bytes of a user's
// download ever leave the machine, which is the only design consistent with
// the rest of Lethe. It answers three questions in one pass:
//
//   1. What is this file really? (magic-byte sniffing, not the extension)
//   2. Does it contradict how it is presented? (name/type mismatch, double
//      extensions, bidi-override filenames, executables dressed as documents)
//   3. Does its content match a known-bad signature or a risky construct?
//      (signature_set.h, plus archive and entropy analysis)
//
// What it is not: a behavioural sandbox, an emulator, or a substitute for
// macOS Gatekeeper and notarisation. It catches presentation attacks and
// known patterns before the user double-clicks, and says plainly what it saw.

#ifndef LETHE_SECURITY_FILE_SCANNER_H
#define LETHE_SECURITY_FILE_SCANNER_H

#include <cstddef>
#include <string>
#include <vector>

#include "security/signature_set.h"
#include "security/threat_report.h"

namespace lethe {

struct ScanOptions {
    // Bytes read from the head of a file for signature scanning. Large
    // downloads are common and a full read would stall the download UI;
    // droppers and document payloads live near the start of a file.
    size_t maxScanBytes = 8u * 1024u * 1024u;
    // Parse zip central directories and inspect entry names/ratios.
    bool inspectArchives = true;
    // Treat macOS executable formats as dangerous by default. Turning this
    // off is for tests, not for shipping configurations.
    bool flagExecutables = true;
};

// Sniffed content type. `label` is what the user is shown.
struct ContentIdentity {
    ContentClass contentClass = ContentClass::Any;
    std::string label;          // "Mach-O executable", "ZIP archive", ...
    bool executable = false;    // runnable code once the quarantine bit is off
    bool archive = false;
};

// Identify by magic bytes. Never trusts the extension.
ContentIdentity identifyContent(const void* data, size_t length);

// Shannon entropy of a buffer, in bits per byte (0-8). High entropy in a
// file that claims to be a document is evidence of packing or encryption.
double shannonEntropy(const void* data, size_t length);

// Scan a buffer that was downloaded as \p fileName from \p sourceUrl. Both
// may be empty; the name and origin only add findings, they are never
// required.
ThreatReport scanDownloadBuffer(const std::string& fileName,
                                const std::string& sourceUrl,
                                const void* data, size_t length,
                                const ScanOptions& options = {});

// Scan a file already written to disk. Reads at most options.maxScanBytes.
ThreatReport scanDownloadFile(const std::string& path,
                              const std::string& sourceUrl,
                              const ScanOptions& options = {});

// Extensions macOS will execute (directly or through an installer). Exposed
// for the shell's own UI copy and for tests.
bool isExecutableExtension(const std::string& extensionLower);

}  // namespace lethe

#endif  // LETHE_SECURITY_FILE_SCANNER_H
