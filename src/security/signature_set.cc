// signature_set.cc - see include/security/signature_set.h

#include "security/signature_set.h"

#include <algorithm>
#include <deque>
#include <mutex>
#include <unordered_map>

#include <openssl/evp.h>

namespace lethe {
namespace {

// Aho-Corasick node. Children are held in a map rather than a 256-wide array
// because the built-in set is a few dozen patterns over mostly-ASCII bytes;
// a dense table per node would cost far more memory than it saves in lookups
// at this size.
struct Node {
    std::unordered_map<uint8_t, int> next;
    int fail = 0;
    std::vector<int> outputs;   // indices into signatures_
};

bool classMatches(ContentClass required, ContentClass actual) {
    return required == ContentClass::Any || required == actual;
}

}  // namespace

struct SignatureSet::Impl {
    std::vector<ByteSignature> signatures;
    std::unordered_map<std::string, std::string> hashes;  // hex -> name
    std::vector<Node> nodes;
    bool built = false;

    void build() {
        nodes.clear();
        nodes.emplace_back();
        for (size_t i = 0; i < signatures.size(); ++i) {
            const std::string& pattern = signatures[i].pattern;
            if (pattern.empty()) continue;
            int node = 0;
            for (unsigned char c : pattern) {
                auto it = nodes[node].next.find(c);
                if (it == nodes[node].next.end()) {
                    nodes.emplace_back();
                    const int created = static_cast<int>(nodes.size()) - 1;
                    nodes[node].next[c] = created;
                    node = created;
                } else {
                    node = it->second;
                }
            }
            nodes[node].outputs.push_back(static_cast<int>(i));
        }

        // Breadth-first failure links: the classic construction, where a node
        // inherits the outputs of the longest proper suffix that is also a
        // prefix of some pattern.
        std::deque<int> queue;
        for (auto& [byte, child] : nodes[0].next) {
            (void)byte;
            nodes[child].fail = 0;
            queue.push_back(child);
        }
        while (!queue.empty()) {
            const int node = queue.front();
            queue.pop_front();
            // Copy the child map: adding fail links does not mutate it, but
            // the vector can reallocate while we walk, invalidating iterators.
            const std::unordered_map<uint8_t, int> children = nodes[node].next;
            for (const auto& [byte, child] : children) {
                int fail = nodes[node].fail;
                while (fail != 0 && nodes[fail].next.find(byte) == nodes[fail].next.end())
                    fail = nodes[fail].fail;
                auto it = nodes[fail].next.find(byte);
                nodes[child].fail = (it != nodes[fail].next.end() && it->second != child)
                                        ? it->second
                                        : 0;
                const std::vector<int> inherited = nodes[nodes[child].fail].outputs;
                nodes[child].outputs.insert(nodes[child].outputs.end(),
                                            inherited.begin(), inherited.end());
                queue.push_back(child);
            }
        }
        built = true;
    }
};

SignatureSet::SignatureSet() : impl_(std::make_unique<Impl>()) {}
SignatureSet::~SignatureSet() = default;
SignatureSet::SignatureSet(SignatureSet&&) noexcept = default;
SignatureSet& SignatureSet::operator=(SignatureSet&&) noexcept = default;

void SignatureSet::addSignature(ByteSignature signature) {
    impl_->signatures.push_back(std::move(signature));
    impl_->built = false;
}

void SignatureSet::addHash(const std::string& sha256Hex, const std::string& name) {
    std::string key = sha256Hex;
    std::transform(key.begin(), key.end(), key.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    impl_->hashes[key] = name;
}

void SignatureSet::build() {
    if (!impl_->built) impl_->build();
}

std::vector<SignatureHit> SignatureSet::scan(const void* data, size_t length,
                                             ContentClass contentClass) const {
    std::vector<SignatureHit> hits;
    if (!data || length == 0 || impl_->signatures.empty()) return hits;
    if (!impl_->built) impl_->build();

    const auto* bytes = static_cast<const unsigned char*>(data);
    std::vector<char> seen(impl_->signatures.size(), 0);
    int node = 0;
    for (size_t i = 0; i < length; ++i) {
        const uint8_t c = bytes[i];
        while (node != 0 && impl_->nodes[node].next.find(c) == impl_->nodes[node].next.end())
            node = impl_->nodes[node].fail;
        auto it = impl_->nodes[node].next.find(c);
        node = (it == impl_->nodes[node].next.end()) ? 0 : it->second;
        for (int index : impl_->nodes[node].outputs) {
            if (seen[static_cast<size_t>(index)]) continue;
            const ByteSignature& signature = impl_->signatures[static_cast<size_t>(index)];
            if (!classMatches(signature.appliesTo, contentClass)) continue;
            seen[static_cast<size_t>(index)] = 1;
            SignatureHit hit;
            hit.signature = &signature;
            hit.offset = i + 1 >= signature.pattern.size()
                             ? i + 1 - signature.pattern.size()
                             : 0;
            hits.push_back(hit);
        }
    }
    return hits;
}

std::string SignatureSet::matchHash(const std::string& sha256Hex) const {
    std::string key = sha256Hex;
    std::transform(key.begin(), key.end(), key.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    auto it = impl_->hashes.find(key);
    return it == impl_->hashes.end() ? std::string() : it->second;
}

size_t SignatureSet::signatureCount() const { return impl_->signatures.size(); }
size_t SignatureSet::hashCount() const { return impl_->hashes.size(); }

std::string sha256Hex(const void* data, size_t length) {
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digestLength = 0;
    if (EVP_Digest(data, length, digest, &digestLength, EVP_sha256(), nullptr) != 1)
        return std::string();
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(digestLength * 2);
    for (unsigned int i = 0; i < digestLength; ++i) {
        out.push_back(hex[digest[i] >> 4]);
        out.push_back(hex[digest[i] & 0x0f]);
    }
    return out;
}

const SignatureSet& builtinSignatureSet() {
    static SignatureSet* set = [] {
        auto* s = new SignatureSet();

        // The EICAR anti-malware test file. Every scanner is expected to
        // detect it, and it is the only pattern here that justifies the
        // Malicious verdict on its own.
        s->addSignature({"sig.eicar",
                         "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                         ContentClass::Any, ThreatSeverity::Malicious, 100,
                         "EICAR anti-malware test file"});

        // Shell droppers: fetch-and-execute in one line. Restricted to
        // scripts so a blog post describing the pattern is not flagged.
        s->addSignature({"sig.curl_pipe_shell", "curl", ContentClass::Script,
                         ThreatSeverity::Notice, 5,
                         "script downloads with curl"});
        s->addSignature({"sig.pipe_to_shell", "| sh", ContentClass::Script,
                         ThreatSeverity::Suspicious, 25,
                         "script pipes downloaded data into a shell"});
        s->addSignature({"sig.pipe_to_bash", "| bash", ContentClass::Script,
                         ThreatSeverity::Suspicious, 25,
                         "script pipes downloaded data into a shell"});
        s->addSignature({"sig.osascript_admin", "with administrator privileges",
                         ContentClass::Script, ThreatSeverity::Dangerous, 45,
                         "script asks for administrator privileges"});
        s->addSignature({"sig.launchagent_write", "Library/LaunchAgents",
                         ContentClass::Script, ThreatSeverity::Suspicious, 30,
                         "script installs a login persistence item"});
        s->addSignature({"sig.chmod_exec", "chmod +x", ContentClass::Script,
                         ThreatSeverity::Notice, 10,
                         "script marks a file executable"});
        s->addSignature({"sig.base64_decode_exec", "base64 -d", ContentClass::Script,
                         ThreatSeverity::Suspicious, 20,
                         "script decodes an embedded base64 payload"});

        // PowerShell download cradles, seen in cross-platform phishing kits.
        s->addSignature({"sig.powershell_hidden", "-WindowStyle Hidden",
                         ContentClass::Script, ThreatSeverity::Suspicious, 25,
                         "PowerShell is invoked with a hidden window"});
        s->addSignature({"sig.powershell_encoded", "-EncodedCommand",
                         ContentClass::Script, ThreatSeverity::Dangerous, 40,
                         "PowerShell runs a base64-encoded command"});
        s->addSignature({"sig.powershell_download", "DownloadString",
                         ContentClass::Script, ThreatSeverity::Suspicious, 25,
                         "PowerShell downloads and runs remote code"});

        // Documents that execute on open.
        s->addSignature({"sig.pdf_openaction_js", "/OpenAction", ContentClass::Document,
                         ThreatSeverity::Suspicious, 25,
                         "PDF runs an action when opened"});
        s->addSignature({"sig.pdf_javascript", "/JavaScript", ContentClass::Document,
                         ThreatSeverity::Suspicious, 25,
                         "PDF embeds JavaScript"});
        s->addSignature({"sig.pdf_launch", "/Launch", ContentClass::Document,
                         ThreatSeverity::Dangerous, 45,
                         "PDF launches an external program"});
        s->addSignature({"sig.ole_macro", "vbaProject.bin", ContentClass::Archive,
                         ThreatSeverity::Suspicious, 30,
                         "Office document contains a VBA macro project"});
        s->addSignature({"sig.vba_autoopen", "AutoOpen", ContentClass::Document,
                         ThreatSeverity::Dangerous, 40,
                         "document macro runs automatically on open"});

        // HTML smuggling: the page assembles a binary in JavaScript and
        // triggers a download without ever fetching one.
        s->addSignature({"sig.html_blob_download", "msSaveOrOpenBlob", ContentClass::Html,
                         ThreatSeverity::Suspicious, 30,
                         "page builds a file in JavaScript and saves it"});
        s->addSignature({"sig.html_data_download", "download=\"", ContentClass::Html,
                         ThreatSeverity::Notice, 5,
                         "page triggers a download from markup"});
        return s;
    }();
    set->build();
    return *set;
}

}  // namespace lethe
