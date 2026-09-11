// signature_set.h - multi-pattern content signatures for the file scanner
//
// The scanner must look for many byte patterns in one pass over a file that
// can be hundreds of megabytes: running one substring search per signature
// is quadratic in the number of signatures. This is an Aho-Corasick automaton
// built once from the signature list, so a scan costs one linear pass
// regardless of how many patterns are loaded.
//
// Signatures here are deliberately conservative. A browser scanner that
// guesses wrong is worse than none: users learn to click through warnings.
// Every built-in pattern either identifies a well-known test artifact, or
// pairs with a format check in file_scanner so it cannot fire on innocent
// text that merely contains the same bytes.

#ifndef LETHE_SECURITY_SIGNATURE_SET_H
#define LETHE_SECURITY_SIGNATURE_SET_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "security/threat_report.h"

namespace lethe {

// A file class the signature applies to. A pattern restricted to a class is
// only reported when the scanner sniffed that class, which is what keeps
// "eval(atob(" from firing inside a dictionary of JavaScript documentation.
enum class ContentClass {
    Any = 0,
    Executable,   // Mach-O, PE, ELF
    Script,       // shell, python, javascript, powershell, vbs
    Document,     // PDF, OLE, OOXML
    Archive,      // zip family
    Html,
};

struct ByteSignature {
    std::string id;
    std::string pattern;        // raw bytes (not a regex)
    ContentClass appliesTo = ContentClass::Any;
    ThreatSeverity severity = ThreatSeverity::Suspicious;
    int score = 20;
    std::string detail;         // shown to the user when it fires
};

struct SignatureHit {
    const ByteSignature* signature = nullptr;
    size_t offset = 0;
};

class SignatureSet {
 public:
    SignatureSet();
    ~SignatureSet();
    SignatureSet(SignatureSet&&) noexcept;
    SignatureSet& operator=(SignatureSet&&) noexcept;

    void addSignature(ByteSignature signature);
    // Full-file SHA-256, lowercase hex. Any match is reported as Malicious.
    void addHash(const std::string& sha256Hex, const std::string& name);

    // Compiles the automaton. Called lazily by scan() when needed.
    void build();

    // One linear pass. Only signatures whose class is Any or \p contentClass
    // are reported. At most one hit per signature (the first) is returned.
    std::vector<SignatureHit> scan(const void* data, size_t length,
                                   ContentClass contentClass) const;

    // Name of the blocked hash, or empty when unknown.
    std::string matchHash(const std::string& sha256Hex) const;

    size_t signatureCount() const;
    size_t hashCount() const;

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Lethe's built-in signature set (shared, immutable, built on first use).
const SignatureSet& builtinSignatureSet();

// Lowercase hex SHA-256 of a buffer.
std::string sha256Hex(const void* data, size_t length);

}  // namespace lethe

#endif  // LETHE_SECURITY_SIGNATURE_SET_H
