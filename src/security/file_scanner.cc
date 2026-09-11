// file_scanner.cc - see include/security/file_scanner.h

#include "security/file_scanner.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>

namespace lethe {
namespace {

bool startsWith(const unsigned char* data, size_t length, const char* magic,
                size_t magicLength) {
    return length >= magicLength && std::memcmp(data, magic, magicLength) == 0;
}

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

// Final extension, lowercase, without the dot. Empty when there is none.
std::string extensionOf(const std::string& name) {
    const size_t slash = name.find_last_of("/\\");
    const std::string base = slash == std::string::npos ? name : name.substr(slash + 1);
    const size_t dot = base.find_last_of('.');
    if (dot == std::string::npos || dot + 1 >= base.size()) return std::string();
    return toLower(base.substr(dot + 1));
}

std::vector<std::string> extensionChain(const std::string& name) {
    const size_t slash = name.find_last_of("/\\");
    std::string base = slash == std::string::npos ? name : name.substr(slash + 1);
    std::vector<std::string> parts;
    size_t pos = 0;
    while ((pos = base.find('.')) != std::string::npos) {
        base = base.substr(pos + 1);
        const size_t next = base.find('.');
        parts.push_back(toLower(next == std::string::npos ? base : base.substr(0, next)));
        if (next == std::string::npos) break;
    }
    return parts;
}

// Extensions that commonly masquerade: a document type a user expects to be
// inert, used as the first half of a double extension.
bool isDocumentExtension(const std::string& ext) {
    static const char* kDocs[] = {"pdf", "doc", "docx", "xls", "xlsx", "ppt",
                                  "pptx", "txt", "rtf", "jpg", "jpeg", "png",
                                  "gif", "mp3", "mp4", "csv", "json"};
    for (const char* candidate : kDocs)
        if (ext == candidate) return true;
    return false;
}

bool containsBidiOverride(const std::string& name) {
    // U+202E RIGHT-TO-LEFT OVERRIDE (and friends) reverse how the rest of a
    // filename renders, so "exe.txt" displays as "txt.exe" - the classic
    // filename spoof. UTF-8: E2 80 AA..AE and E2 81 A6..A9.
    for (size_t i = 0; i + 2 < name.size(); ++i) {
        const auto a = static_cast<unsigned char>(name[i]);
        const auto b = static_cast<unsigned char>(name[i + 1]);
        const auto c = static_cast<unsigned char>(name[i + 2]);
        if (a == 0xE2 && b == 0x80 && c >= 0xAA && c <= 0xAE) return true;
        if (a == 0xE2 && b == 0x81 && c >= 0xA6 && c <= 0xA9) return true;
    }
    return false;
}

struct ZipEntry {
    std::string name;
    uint64_t compressedSize = 0;
    uint64_t uncompressedSize = 0;
    bool encrypted = false;
};

uint16_t readU16(const unsigned char* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t readU32(const unsigned char* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// Walks local file headers from the start of the buffer. The central
// directory is authoritative for a complete file, but a download scanner
// often sees only the head of a large archive, and local headers are enough
// to learn entry names, sizes and the encryption bit.
std::vector<ZipEntry> parseZipEntries(const unsigned char* data, size_t length,
                                      size_t maxEntries = 512) {
    std::vector<ZipEntry> entries;
    size_t offset = 0;
    while (offset + 30 <= length && entries.size() < maxEntries) {
        if (readU32(data + offset) != 0x04034b50u) break;
        ZipEntry entry;
        const uint16_t flags = readU16(data + offset + 6);
        entry.encrypted = (flags & 0x0001u) != 0;
        entry.compressedSize = readU32(data + offset + 18);
        entry.uncompressedSize = readU32(data + offset + 22);
        const uint16_t nameLength = readU16(data + offset + 26);
        const uint16_t extraLength = readU16(data + offset + 28);
        const size_t nameStart = offset + 30;
        if (nameStart + nameLength > length) break;
        entry.name.assign(reinterpret_cast<const char*>(data + nameStart), nameLength);
        entries.push_back(entry);
        const size_t next = nameStart + nameLength + extraLength + entry.compressedSize;
        if (next <= offset) break;   // malformed: refuse to loop
        offset = next;
    }
    return entries;
}

void scanZipEntries(const unsigned char* data, size_t length, ThreatReport& report) {
    const std::vector<ZipEntry> entries = parseZipEntries(data, length);
    if (entries.empty()) return;
    uint64_t totalCompressed = 0;
    uint64_t totalUncompressed = 0;
    bool sawExecutable = false;
    bool sawEncrypted = false;
    for (const ZipEntry& entry : entries) {
        totalCompressed += entry.compressedSize;
        totalUncompressed += entry.uncompressedSize;
        sawEncrypted = sawEncrypted || entry.encrypted;
        // Zip-slip: an entry that escapes the extraction directory.
        if (entry.name.find("../") != std::string::npos ||
            (!entry.name.empty() && entry.name.front() == '/')) {
            addFinding(report, {"archive.path_traversal",
                                "archive entry escapes its folder: " + entry.name,
                                ThreatSeverity::Dangerous, 45});
        }
        const std::string ext = extensionOf(entry.name);
        if (isExecutableExtension(ext)) sawExecutable = true;
    }
    if (sawExecutable) {
        addFinding(report, {"archive.contains_executable",
                            "archive contains an executable entry",
                            ThreatSeverity::Suspicious, 25});
    }
    if (sawEncrypted) {
        // Password-protected archives are the standard way to post malware
        // past a scanner; the password then arrives in the same email.
        addFinding(report, {"archive.encrypted",
                            "archive is password protected, so its contents "
                            "cannot be inspected",
                            ThreatSeverity::Suspicious, 30});
    }
    if (totalCompressed > 0 && totalUncompressed / std::max<uint64_t>(1, totalCompressed) > 200) {
        addFinding(report, {"archive.high_expansion",
                            "archive expands more than 200x, which is "
                            "characteristic of a decompression bomb",
                            ThreatSeverity::Suspicious, 30});
    }
}

}  // namespace

bool isExecutableExtension(const std::string& extensionLower) {
    static const char* kExecutable[] = {
        "exe", "scr", "com", "bat", "cmd", "msi", "ps1", "vbs", "js", "jse",
        "wsf", "hta", "jar", "app", "pkg", "dmg", "command", "workflow",
        "scpt", "applescript", "sh", "zsh", "bash", "py", "rb", "pl", "term",
        "prefpane", "kext", "dylib", "so", "elf", "run", "appimage", "deb",
        "rpm", "lnk"};
    for (const char* candidate : kExecutable)
        if (extensionLower == candidate) return true;
    return false;
}

ContentIdentity identifyContent(const void* dataVoid, size_t length) {
    ContentIdentity identity;
    const auto* data = static_cast<const unsigned char*>(dataVoid);
    if (!data || length < 4) return identity;

    // Mach-O (thin and fat, both endians) and dyld shared objects.
    static const std::array<uint32_t, 6> kMachOMagic = {
        0xfeedfaceu, 0xcefaedfeu, 0xfeedfacfu, 0xcffaedfeu,  // thin
        0xcafebabeu, 0xbebafecau};                           // universal
    const uint32_t leading = readU32(data);
    for (uint32_t magic : kMachOMagic) {
        if (leading == magic) {
            // 0xcafebabe is also the Java class-file magic; Java class files
            // are not directly executable by macOS, so distinguish them by
            // the version words that follow.
            if (magic == 0xcafebabeu && length >= 8 && readU16(data + 6) == 0 &&
                data[4] == 0 && data[5] == 0) {
                identity.label = "Java class file";
                identity.contentClass = ContentClass::Executable;
                identity.executable = true;
                return identity;
            }
            identity.label = "Mach-O executable";
            identity.contentClass = ContentClass::Executable;
            identity.executable = true;
            return identity;
        }
    }
    if (startsWith(data, length, "MZ", 2)) {
        identity.label = "Windows PE executable";
        identity.contentClass = ContentClass::Executable;
        identity.executable = true;
        return identity;
    }
    if (startsWith(data, length, "\x7f" "ELF", 4)) {
        identity.label = "ELF executable";
        identity.contentClass = ContentClass::Executable;
        identity.executable = true;
        return identity;
    }
    if (startsWith(data, length, "PK\x03\x04", 4) ||
        startsWith(data, length, "PK\x05\x06", 4)) {
        identity.label = "ZIP archive";
        identity.contentClass = ContentClass::Archive;
        identity.archive = true;
        return identity;
    }
    if (startsWith(data, length, "%PDF", 4)) {
        identity.label = "PDF document";
        identity.contentClass = ContentClass::Document;
        return identity;
    }
    if (startsWith(data, length, "\xd0\xcf\x11\xe0", 4)) {
        identity.label = "OLE compound document";
        identity.contentClass = ContentClass::Document;
        return identity;
    }
    if (startsWith(data, length, "#!", 2)) {
        identity.label = "script with interpreter line";
        identity.contentClass = ContentClass::Script;
        identity.executable = true;
        return identity;
    }
    if (startsWith(data, length, "\x1f\x8b", 2)) {
        identity.label = "gzip archive";
        identity.contentClass = ContentClass::Archive;
        identity.archive = true;
        return identity;
    }
    if (length >= 6 && (startsWith(data, length, "GIF87a", 6) ||
                        startsWith(data, length, "GIF89a", 6))) {
        identity.label = "GIF image";
        return identity;
    }
    if (startsWith(data, length, "\x89PNG", 4)) {
        identity.label = "PNG image";
        return identity;
    }
    if (startsWith(data, length, "\xff\xd8\xff", 3)) {
        identity.label = "JPEG image";
        return identity;
    }

    // Text-ish content: decide between HTML and plain script/text.
    const size_t probe = std::min<size_t>(length, 1024);
    std::string head(reinterpret_cast<const char*>(data), probe);
    const std::string lowerHead = toLower(head);
    if (lowerHead.find("<html") != std::string::npos ||
        lowerHead.find("<!doctype html") != std::string::npos ||
        lowerHead.find("<script") != std::string::npos) {
        identity.label = "HTML document";
        identity.contentClass = ContentClass::Html;
        return identity;
    }
    bool printable = true;
    for (size_t i = 0; i < probe; ++i) {
        const unsigned char c = data[i];
        if (c == 0) { printable = false; break; }
    }
    if (printable) {
        identity.label = "text";
        identity.contentClass = ContentClass::Script;
    }
    return identity;
}

double shannonEntropy(const void* dataVoid, size_t length) {
    if (!dataVoid || length == 0) return 0.0;
    const auto* data = static_cast<const unsigned char*>(dataVoid);
    std::array<size_t, 256> counts{};
    for (size_t i = 0; i < length; ++i) counts[data[i]]++;
    double entropy = 0.0;
    for (size_t count : counts) {
        if (count == 0) continue;
        const double p = static_cast<double>(count) / static_cast<double>(length);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

ThreatReport scanDownloadBuffer(const std::string& fileName,
                                const std::string& sourceUrl,
                                const void* dataVoid, size_t length,
                                const ScanOptions& options) {
    ThreatReport report;
    report.subject = fileName.empty() ? sourceUrl : fileName;
    const auto* data = static_cast<const unsigned char*>(dataVoid);
    const size_t scanLength = std::min(length, options.maxScanBytes);

    const ContentIdentity identity = identifyContent(data, scanLength);
    report.identifiedType = identity.label;

    // 1. Known-bad by full-file hash. Only meaningful when the whole file is
    //    in the buffer; a truncated read would hash to something else.
    if (data && length > 0 && length <= options.maxScanBytes) {
        const std::string hash = sha256Hex(data, length);
        const std::string name = builtinSignatureSet().matchHash(hash);
        if (!name.empty()) {
            addFinding(report, {"file.known_malware",
                                "matches known malware: " + name,
                                ThreatSeverity::Malicious, 100});
            return report;
        }
    }

    // 2. Presentation: what the name claims versus what the bytes are.
    const std::string ext = extensionOf(fileName);
    const std::vector<std::string> chain = extensionChain(fileName);
    if (containsBidiOverride(fileName)) {
        addFinding(report, {"file.bidi_filename",
                            "file name contains a text-direction override, "
                            "which hides its real extension",
                            ThreatSeverity::Dangerous, 50});
    }
    if (chain.size() >= 2 && isDocumentExtension(chain[chain.size() - 2]) &&
        isExecutableExtension(chain.back())) {
        addFinding(report, {"file.double_extension",
                            "file is named like a document but ends in ." +
                                chain.back(),
                            ThreatSeverity::Dangerous, 50});
    }
    if (identity.executable && !ext.empty() && isDocumentExtension(ext)) {
        addFinding(report, {"file.type_mismatch",
                            "content is a " + identity.label +
                                " but the name claims ." + ext,
                            ThreatSeverity::Dangerous, 50});
    }

    // 3. Class of content. An executable from the web is not malware, but it
    //    is the category where a mistake is unrecoverable, so it is always
    //    surfaced.
    if (options.flagExecutables && identity.executable) {
        addFinding(report, {"file.executable",
                            "downloaded file is executable code (" +
                                identity.label + ")",
                            ThreatSeverity::Suspicious, 25});
    } else if (options.flagExecutables && isExecutableExtension(ext)) {
        addFinding(report, {"file.executable_extension",
                            "downloaded file has the executable extension ." + ext,
                            ThreatSeverity::Suspicious, 25});
    }

    // 4. Origin. Plain http gives an on-path attacker the ability to swap
    //    the payload, which matters far more for runnable content.
    if (sourceUrl.rfind("http://", 0) == 0 &&
        (identity.executable || isExecutableExtension(ext))) {
        addFinding(report, {"file.insecure_origin",
                            "executable was downloaded over plain http",
                            ThreatSeverity::Dangerous, 40});
    }

    // 5. Content signatures.
    if (data && scanLength > 0) {
        for (const SignatureHit& hit :
             builtinSignatureSet().scan(data, scanLength, identity.contentClass)) {
            addFinding(report, {hit.signature->id, hit.signature->detail,
                                hit.signature->severity, hit.signature->score});
        }
    }

    // 6. Structure.
    if (options.inspectArchives && identity.archive && data)
        scanZipEntries(data, scanLength, report);

    // 7. Entropy. Compressed and encrypted data is legitimately high entropy,
    //    so this only means something for content that should be text.
    if (data && scanLength >= 4096 && !identity.archive &&
        (identity.contentClass == ContentClass::Document ||
         identity.contentClass == ContentClass::Script)) {
        const double entropy = shannonEntropy(data, scanLength);
        if (entropy > 7.5) {
            addFinding(report, {"file.high_entropy",
                                "content is packed or encrypted (entropy " +
                                    std::to_string(entropy).substr(0, 4) + " bits/byte)",
                                ThreatSeverity::Suspicious, 20});
        }
    }

    return report;
}

ThreatReport scanDownloadFile(const std::string& path,
                              const std::string& sourceUrl,
                              const ScanOptions& options) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        ThreatReport report;
        report.subject = path;
        addFinding(report, {"file.unreadable", "file could not be read for scanning",
                            ThreatSeverity::Notice, 0});
        return report;
    }
    std::vector<char> buffer(options.maxScanBytes);
    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const size_t read = static_cast<size_t>(file.gcount());
    buffer.resize(read);
    ThreatReport report = scanDownloadBuffer(path, sourceUrl, buffer.data(), read, options);
    report.subject = path;
    return report;
}

}  // namespace lethe
