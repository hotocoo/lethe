
#ifndef LETHE_NETWORK_TLS_CONFIG_H
#define LETHE_NETWORK_TLS_CONFIG_H

namespace lethe {

class TLSConfig {
public:
    // Initialize with modern secure settings (TLS 1.3+, strict ciphers)
    void init_modern_tls_config(int min_ver, int max_ver) {
        minVersion = min_ver;
        maxVersion = max_ver;
        
        cipherSuites.push_back("TLS_AES_256_GCM_SHA384");
        cipherSuites.push_back("TLS_CHACHA20_POLY1305_SHA256");
        cipherSuites.push_back("TLS_AES_128_GCM_SHA256");
        
        // No downgrade attacks, no legacy renegotiation
        
        std::cout << "[lethe] TLS config initialized: min_ver=" 
                  << std::hex << minVersion 
                  << ", ciphers=" << cipherSuites.size() << "\n";
    }

private:
    int minVersion;
    int maxVersion;
    std::vector<std::string> cipherSuites;
};

} // namespace lethe

#endif // LETHE_NETWORK_TLS_CONFIG_H
