#ifndef LETHE_TESTS_TEST_TLS_HELPERS_H
#define LETHE_TESTS_TEST_TLS_HELPERS_H

// test_tls_helpers.h — OpenSSL test double for HTTPS e2e tests.
//
// Provides a throwaway certificate authority (mini-CA), server certificates
// signed by it, and a minimal loopback TLS server. Tests hand the CA PEM to
// the engine via Config.caBundlePath so a REAL certificate-verified TLS
// handshake can be exercised end to end without touching the system store.

#include <cstring>
#include <functional>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

namespace lethe {
namespace tls_test {

#ifdef HAVE_OPENSSL

inline bool addX509Ext(X509* cert, int nid, const char* value) {
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, nid, value);
    if (!ext) return false;
    const bool ok = X509_add_ext(cert, ext, -1) == 1;
    X509_EXTENSION_free(ext);
    return ok;
}

inline bool pemFromCert(X509* cert, std::string& pem) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    PEM_write_bio_X509(bio, cert);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    pem.assign(data, static_cast<size_t>(len));
    BIO_free(bio);
    return len > 0;
}

inline bool pemFromKey(EVP_PKEY* key, std::string& pem) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    pem.assign(data, static_cast<size_t>(len));
    BIO_free(bio);
    return len > 0;
}

// Self-signed CA certificate (basicConstraints CA:TRUE, keyCertSign).
inline bool generateTestCa(std::string& caCertPem, std::string& caKeyPem) {
    EVP_PKEY* caKey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
    if (!caKey) return false;
    X509* ca = X509_new();
    if (!ca) { EVP_PKEY_free(caKey); return false; }
    X509_set_version(ca, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca), 1);
    X509_gmtime_adj(X509_getm_notBefore(ca), -3600); // clock-skew slack
    X509_gmtime_adj(X509_getm_notAfter(ca), 3600 * 24 * 365);
    X509_set_pubkey(ca, caKey);
    X509_NAME* name = X509_get_subject_name(ca);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Lethe Test CA"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Lethe Tests"), -1, -1, 0);
    X509_set_issuer_name(ca, name);
    const bool exts = addX509Ext(ca, NID_basic_constraints,
                                 "critical,CA:TRUE") &&
                      addX509Ext(ca, NID_key_usage,
                                 "critical,keyCertSign");
    const bool signedOk = X509_sign(ca, caKey, EVP_sha256()) > 0;
    const bool ok = exts && signedOk &&
                    pemFromCert(ca, caCertPem) && pemFromKey(caKey, caKeyPem);
    X509_free(ca);
    if (!ok) EVP_PKEY_free(caKey);
    // caKey ownership transferred to the cert signature; free via EVP below.
    EVP_PKEY_free(caKey);
    return ok;
}

// Server certificate for dnsName (+ IP:127.0.0.1), signed by the test CA.
inline bool generateServerCert(const std::string& caCertPem,
                               const std::string& caKeyPem,
                               const std::string& dnsName,
                               std::string& certPem, std::string& keyPem) {
    BIO* caCertBio = BIO_new_mem_buf(caCertPem.data(),
                                     static_cast<int>(caCertPem.size()));
    X509* ca = PEM_read_bio_X509(caCertBio, nullptr, nullptr, nullptr);
    BIO_free(caCertBio);
    BIO* caKeyBio = BIO_new_mem_buf(caKeyPem.data(),
                                    static_cast<int>(caKeyPem.size()));
    EVP_PKEY* caKey = PEM_read_bio_PrivateKey(caKeyBio, nullptr, nullptr, nullptr);
    BIO_free(caKeyBio);
    if (!ca || !caKey) { if (ca) X509_free(ca); if (caKey) EVP_PKEY_free(caKey); return false; }

    EVP_PKEY* srvKey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
    X509* srv = X509_new();
    bool ok = srvKey && srv;
    if (ok) {
        X509_set_version(srv, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(srv), 7);
        X509_gmtime_adj(X509_getm_notBefore(srv), -3600);
        X509_gmtime_adj(X509_getm_notAfter(srv), 3600 * 24 * 365);
        X509_set_pubkey(srv, srvKey);
        X509_NAME* subj = X509_get_subject_name(srv);
        X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(dnsName.c_str()), -1, -1, 0);
        X509_set_issuer_name(srv, X509_get_subject_name(ca));
        const std::string san = "DNS:" + dnsName + ", IP:127.0.0.1";
        ok = addX509Ext(srv, NID_subject_alt_name, san.c_str()) &&
             addX509Ext(srv, NID_ext_key_usage, "serverAuth") &&
             X509_sign(srv, caKey, EVP_sha256()) > 0 &&
             pemFromCert(srv, certPem) && pemFromKey(srvKey, keyPem);
    }
    X509_free(srv);
    EVP_PKEY_free(srvKey);
    X509_free(ca);
    EVP_PKEY_free(caKey);
    return ok;
}

#endif // HAVE_OPENSSL

// Write text to a fresh temp file and return its path ("" on failure).
inline std::string writeTempFile(const std::string& prefix,
                                 const std::string& content) {
    const std::string path = "/tmp/" + prefix + "_" +
                             std::to_string(::getpid()) + ".pem";
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return "";
    const size_t n = std::fwrite(content.data(), 1, content.size(), f);
    std::fclose(f);
    return n == content.size() ? path : "";
}

#ifdef HAVE_OPENSSL

// Minimal single-threaded loopback TLS server for e2e tests.
class LoopbackTlsServer {
public:
    using Handler = std::function<std::string(const std::string& request)>;

    bool start(const std::string& certPem, const std::string& keyPem) {
        sslCtx_ = SSL_CTX_new(TLS_server_method());
        if (!sslCtx_) return false;
        SSL_CTX_set_min_proto_version(sslCtx_, TLS1_3_VERSION);

        BIO* certBio = BIO_new_mem_buf(certPem.data(),
                                       static_cast<int>(certPem.size()));
        X509* x509 = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
        BIO_free(certBio);
        BIO* keyBio = BIO_new_mem_buf(keyPem.data(),
                                      static_cast<int>(keyPem.size()));
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
        BIO_free(keyBio);
        if (!x509 || !pkey) {
            if (x509) X509_free(x509);
            if (pkey) EVP_PKEY_free(pkey);
            SSL_CTX_free(sslCtx_); sslCtx_ = nullptr;
            return false;
        }
        SSL_CTX_use_certificate(sslCtx_, x509);
        SSL_CTX_use_PrivateKey(sslCtx_, pkey);
        X509_free(x509);
        EVP_PKEY_free(pkey);

        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) { SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; return false; }
        int reuse = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
            ::listen(listenFd_, 16) < 0) {
            ::close(listenFd_); listenFd_ = -1;
            SSL_CTX_free(sslCtx_); sslCtx_ = nullptr;
            return false;
        }
        socklen_t len = sizeof(addr);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);

        running_ = true;
        thread_ = std::thread([this]() { runLoop(); });
        return true;
    }

    int port() const { return port_; }
    void setHandler(Handler h) { handler_ = std::move(h); }

    ~LoopbackTlsServer() {
        running_ = false;
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
            listenFd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
        if (sslCtx_) SSL_CTX_free(sslCtx_);
    }

private:
    void runLoop() {
        while (running_.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listenFd_, &rfds);
            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            const int sel = ::select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv);
            if (sel <= 0) continue;
            const int fd = ::accept(listenFd_, nullptr, nullptr);
            if (fd >= 0) handleConnection(fd);
        }
    }

    void handleConnection(int fd) {
        SSL* ssl = SSL_new(sslCtx_);
        if (!ssl) { ::close(fd); return; }
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) != 1) {
            SSL_free(ssl);
            ::close(fd);
            return;
        }
        std::string request;
        char buf[4096];
        while (request.find("\r\n\r\n") == std::string::npos) {
            const int n = SSL_read(ssl, buf, sizeof(buf));
            if (n <= 0) break;
            request.append(buf, static_cast<size_t>(n));
        }
        const std::string resp = handler_(request);
        SSL_write(ssl, resp.data(), static_cast<int>(resp.size()));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(fd);
    }

    SSL_CTX* sslCtx_ = nullptr;
    int listenFd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{false};
    std::thread thread_;
    Handler handler_;
};

#endif // HAVE_OPENSSL

} // namespace tls_test
} // namespace lethe

#endif // LETHE_TESTS_TEST_TLS_HELPERS_H
