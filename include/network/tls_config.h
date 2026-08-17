#ifndef LETHE_NETWORK_TLS_CONFIG_H
#define LETHE_NETWORK_TLS_CONFIG_H

namespace lethe {

// TLS configuration for secure connections
class TLSConfig {
public:
    // Minimum and maximum TLS version allowed (RFC 5246)
    int minVersion;
    int maxVersion;
    
    // Cipher suites (OpenSSL-compatible names)
    std::vector<std::string> cipherSuites;
    
    TLSConfig();
    
    // Initialize with modern secure settings (TLS 1.3+, strict ciphers)
    void initModernStrict();
    
    // Apply to connection context (platform-specific backend)
    bool applyToConnection(void* ctx);
};

} // namespace lethe

#endif // LETHE_NETWORK_TLS_CONFIG_H
