
#ifndef LETHE_CONFIG_H
#define LETHE_CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace lethe {

const std::string VERSION = "1.0.0";
const std::string NAME = "Lethe";
const std::string USER_AGENT_STRING = 
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36";

const bool ENABLE_HARDENED_BUILD = true;
const bool ENABLE_SANDBOXING = true;
const bool ENABLE_DOH = true;
const bool ENFORCE_STRICT_CSP = true;

const int MAX_OPEN_CONNECTIONS = 128;
const int MAX_CONNECTIONS_PER_HOST = 16;
const uint64_t NETWORK_BUFFER_SIZE = 65536;

const uint64_t MAX_MEMORY_PER_PROCESS = 1ULL << 30; // 1GB
const uint64_t TOTAL_MAX_MEMORY = 4ULL << 30; // 4GB total

const std::vector<std::string> DOH_PROVIDERS = {
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query"
};

const int MIN_TLS_VERSION = 0x0304; // TLS 1.3 floor
const int MAX_TLS_VERSION = 0x0305; // TLS 1.3
const std::string DEFAULT_CIPHERS = 
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256";

const std::string DEFAULT_CSP_POLICY = 
    "default-src 'self';"
    "script-src 'self' https://apis.google.com;"
    "style-src 'self';"
    "img-src 'self' data: https: ;"
    "font-src 'self' https://fonts.gstatic.com;"
    "media-src 'self';"
    "frame-src 'none';"
    "object-src 'none';"
    "plugin-types 'none';"
    "base-uri 'self';"
    "form-action 'self';"
    "script-src-elem 'strict-dynamic';"
    "require-trusted-types-for ['default']";

} // namespace lethe

#endif // LETHE_CONFIG_H
