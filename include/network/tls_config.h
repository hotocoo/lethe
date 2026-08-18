#ifndef LETHE_NETWORK_TLS_CONFIG_H
#define LETHE_NETWORK_TLS_CONFIG_H

#include <vector>
#include <string>

namespace lethe {

class TLSConfig {
public:
    TLSConfig() : minVersion(0x0304), maxVersion(0x0305) {}
    
    void init_modern_tls_config(int min_ver, int max_ver) {
        minVersion = min_ver;
        maxVersion = max_ver;
        
        cipherSuites.clear();
        cipherSuites.push_back("TLS_AES_256_GCM_SHA384");
        cipherSuites.push_back("TLS_CHACHA20_POLY1305_SHA256");
        cipherSuites.push_back("TLS_AES_128_GCM_SHA256");
    }
    
    int getMinVersion() const { return minVersion; }
    int getMaxVersion() const { return maxVersion; }
    const std::vector<std::string>& getCipherSuites() const { return cipherSuites; }

private:
    int minVersion;
    int maxVersion;
    std::vector<std::string> cipherSuites;
};

} // namespace lethe

#endif // LETHE_NETWORK_TLS_CONFIG_H