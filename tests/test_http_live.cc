// test_http_live.cc — Live HTTP/HTTPS fetching tests over real sockets
//
// These tests spin up real loopback HTTP and HTTPS servers and verify that
// the HttpClient performs genuine network I/O: TCP connect, (optional) TLS
// handshake, request write, and full response read/parse.

#include "test_framework.h"
#include "network/http_client.h"
#include "network/tls_config.h"
#include "llm/search_service.h"

#include <arpa/inet.h>
#include <cstring>
#include <functional>
#include <map>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <zlib.h>

#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif

using namespace lethe;

namespace {

// Build an HTTP/1.1 response string.
std::string buildHttpResponse(int status, const std::string& statusText,
                              const std::string& body,
                              const std::map<std::string, std::string>& extraHeaders = {}) {
    std::string resp;
    resp += "HTTP/1.1 ";
    resp += std::to_string(status);
    resp += " ";
    resp += statusText;
    resp += "\r\n";
    for (const auto& h : extraHeaders) {
        resp += h.first;
        resp += ": ";
        resp += h.second;
        resp += "\r\n";
    }
    resp += "Content-Length: ";
    resp += std::to_string(body.size());
    resp += "\r\n";
    resp += "Connection: close\r\n";
    resp += "\r\n";
    resp += body;
    return resp;
}

// Gzip-compress data (gzip format, matching the client's 15+16 inflate).
std::string gzipData(const std::string& data) {
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return "";
    }

    std::string out;
    std::vector<Bytef> buf(16384);
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    zs.avail_in = static_cast<uInt>(data.size());

    int ret;
    do {
        zs.next_out = buf.data();
        zs.avail_out = static_cast<uInt>(buf.size());
        ret = deflate(&zs, Z_FINISH);
        size_t have = buf.size() - zs.avail_out;
        out.append(reinterpret_cast<char*>(buf.data()), have);
    } while (ret != Z_STREAM_END);

    deflateEnd(&zs);
    return out;
}

// A minimal single-threaded loopback HTTP server for testing.
class TestHttpServer {
public:
    using Handler = std::function<std::string(const std::string& request)>;

    bool start(int port = 0) {
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) return false;

        int reuse = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(listenFd_); listenFd_ = -1; return false;
        }
        if (::listen(listenFd_, 16) < 0) {
            ::close(listenFd_); listenFd_ = -1; return false;
        }

        sockaddr_in boundAddr;
        socklen_t boundLen = sizeof(boundAddr);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&boundAddr), &boundLen);
        actualPort_ = ntohs(boundAddr.sin_port);

        running_ = true;
        thread_ = std::thread([this]() { runLoop(); });
        return true;
    }

    int port() const { return actualPort_; }

    void stop() {
        running_ = false;
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
            listenFd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~TestHttpServer() { stop(); }

    void setHandler(Handler h) { handler_ = std::move(h); }

private:
    void runLoop() {
        while (running_) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listenFd_, &rfds);
            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 100ms
            int sel = ::select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv);
            if (sel <= 0) continue;

            int clientFd = ::accept(listenFd_, nullptr, nullptr);
            if (clientFd < 0) continue;
            handleConnection(clientFd);
        }
    }

    void handleConnection(int fd) {
        std::string request;
        char buf[4096];
        while (request.find("\r\n\r\n") == std::string::npos) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            request.append(buf, static_cast<size_t>(n));
        }

        if (handler_) {
            std::string response = handler_(request);
            size_t total = 0;
            while (total < response.size()) {
                ssize_t n = ::send(fd, response.data() + total,
                                   response.size() - total, 0);
                if (n <= 0) break;
                total += static_cast<size_t>(n);
            }
        }
        ::close(fd);
    }

    int listenFd_ = -1;
    int actualPort_ = 0;
    bool running_ = false;
    std::thread thread_;
    Handler handler_;
};

#ifdef HAVE_OPENSSL

// Generate a self-signed cert + key as PEM strings.
bool generateSelfSignedCert(std::string& certPem, std::string& keyPem) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    X509* x509 = X509_new();
    if (!x509) { EVP_PKEY_free(pkey); return false; }
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 3600 * 24 * 365);
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(x509, name);
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509); EVP_PKEY_free(pkey); return false;
    }

    BIO* certBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, x509);
    char* certData = nullptr;
    long certLen = BIO_get_mem_data(certBio, &certData);
    certPem.assign(certData, static_cast<size_t>(certLen));

    BIO* keyBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(keyBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* keyData = nullptr;
    long keyLen = BIO_get_mem_data(keyBio, &keyData);
    keyPem.assign(keyData, static_cast<size_t>(keyLen));

    BIO_free(certBio);
    BIO_free(keyBio);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return true;
}

// A minimal single-threaded loopback HTTPS server for testing.
class TestHttpsServer {
public:
    using Handler = std::function<std::string(const std::string& request)>;

    bool start(const std::string& certPem, const std::string& keyPem, int port = 0) {
        sslCtx_ = SSL_CTX_new(TLS_server_method());
        if (!sslCtx_) return false;

        BIO* certBio = BIO_new_mem_buf(certPem.data(), static_cast<int>(certPem.size()));
        X509* x509 = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
        BIO_free(certBio);
        if (!x509) { SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; return false; }

        BIO* keyBio = BIO_new_mem_buf(keyPem.data(), static_cast<int>(keyPem.size()));
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
        BIO_free(keyBio);
        if (!pkey) { X509_free(x509); SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; return false; }

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
        addr.sin_port = htons(port);

        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(listenFd_); listenFd_ = -1;
            SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; return false;
        }
        if (::listen(listenFd_, 16) < 0) {
            ::close(listenFd_); listenFd_ = -1;
            SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; return false;
        }

        sockaddr_in boundAddr;
        socklen_t boundLen = sizeof(boundAddr);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&boundAddr), &boundLen);
        actualPort_ = ntohs(boundAddr.sin_port);

        running_ = true;
        thread_ = std::thread([this]() { runLoop(); });
        return true;
    }

    int port() const { return actualPort_; }

    void stop() {
        running_ = false;
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
            listenFd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
        if (sslCtx_) { SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; }
    }

    ~TestHttpsServer() { stop(); }

    void setHandler(Handler h) { handler_ = std::move(h); }

private:
    void runLoop() {
        while (running_) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listenFd_, &rfds);
            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            int sel = ::select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv);
            if (sel <= 0) continue;

            int clientFd = ::accept(listenFd_, nullptr, nullptr);
            if (clientFd < 0) continue;
            handleConnection(clientFd);
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
            int n = SSL_read(ssl, buf, sizeof(buf));
            if (n <= 0) break;
            request.append(buf, static_cast<size_t>(n));
        }

        if (handler_) {
            std::string response = handler_(request);
            size_t total = 0;
            while (total < response.size()) {
                int n = SSL_write(ssl, response.data() + total,
                                  static_cast<int>(response.size() - total));
                if (n <= 0) break;
                total += static_cast<size_t>(n);
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(fd);
    }

    int listenFd_ = -1;
    int actualPort_ = 0;
    bool running_ = false;
    std::thread thread_;
    SSL_CTX* sslCtx_ = nullptr;
    Handler handler_;
};

#endif // HAVE_OPENSSL

} // namespace

// --- Plain HTTP tests ---

LETHE_TEST_CASE(HttpLive_SimpleGet) {
    TestHttpServer server;
    CHECK_TRUE(server.start(0));
    server.setHandler([](const std::string& req) {
        (void)req;
        return buildHttpResponse(200, "OK", "Hello, live HTTP!");
    });

    TLSConfig tls;
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/index.html";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    std::string body(resp.body.begin(), resp.body.end());
    CHECK_EQ(body, "Hello, live HTTP!");
    CHECK_EQ(resp.headers["content-length"], "17");

    client.shutdown();
}

LETHE_TEST_CASE(HttpLive_CustomHeaders) {
    TestHttpServer server;
    CHECK_TRUE(server.start(0));
    server.setHandler([](const std::string& req) {
        (void)req;
        std::map<std::string, std::string> headers = {
            {"X-Custom", "test-value"},
            {"Content-Type", "text/plain"}
        };
        return buildHttpResponse(200, "OK", "with headers", headers);
    });

    TLSConfig tls;
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.headers["x-custom"], "test-value");
    CHECK_EQ(resp.headers["content-type"], "text/plain");

    client.shutdown();
}

LETHE_TEST_CASE(HttpLive_GzipDecompression) {
    std::string original = "This is a longer body that should be gzip compressed for the test. "
                           "Repeating to make it long enough: 0123456789 0123456789 0123456789.";
    std::string gzipped = gzipData(original);
    CHECK_TRUE(!gzipped.empty());

    TestHttpServer server;
    CHECK_TRUE(server.start(0));
    server.setHandler([&gzipped](const std::string& req) {
        (void)req;
        std::map<std::string, std::string> headers = {
            {"Content-Encoding", "gzip"},
            {"Content-Type", "text/plain"}
        };
        return buildHttpResponse(200, "OK", gzipped, headers);
    });

    TLSConfig tls;
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/gzipped";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    std::string body(resp.body.begin(), resp.body.end());
    // The client should have decompressed the gzip body.
    CHECK_EQ(body, original);

    client.shutdown();
}

LETHE_TEST_CASE(HttpLive_RedirectFollow) {
    TestHttpServer server;
    CHECK_TRUE(server.start(0));
    server.setHandler([](const std::string& req) {
        // If the path is /redirect, send a 302 to /final.
        if (req.find("/redirect") != std::string::npos) {
            std::map<std::string, std::string> headers = {
                {"Location", "/final"}
            };
            return buildHttpResponse(302, "Found", "", headers);
        }
        // Otherwise, return the final content.
        return buildHttpResponse(200, "OK", "final destination");
    });

    TLSConfig tls;
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/redirect";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    std::string body(resp.body.begin(), resp.body.end());
    CHECK_EQ(body, "final destination");
    // The final URL should be /final.
    CHECK_TRUE(resp.finalUrl.find("/final") != std::string::npos);

    client.shutdown();
}

LETHE_TEST_CASE(HttpLive_PostRequest) {
    std::string receivedBody;
    TestHttpServer server;
    CHECK_TRUE(server.start(0));
    server.setHandler([&receivedBody](const std::string& req) {
        // Extract the body (after the blank line).
        size_t blankLine = req.find("\r\n\r\n");
        if (blankLine != std::string::npos) {
            receivedBody = req.substr(blankLine + 4);
        }
        return buildHttpResponse(200, "OK", "received: " + receivedBody);
    });

    TLSConfig tls;
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/submit";
    req.method = HttpMethod::POST;
    req.body = "key1=value1&key2=value2";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    // The server should have received the POST body.
    CHECK_EQ(receivedBody, "key1=value1&key2=value2");

    client.shutdown();
}

LETHE_TEST_CASE(HttpLive_ConnectionRefused) {
    TLSConfig tls;
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    // Connect to a port with no server listening.
    HttpRequest req;
    req.url = "http://127.0.0.1:1/"; // port 1, almost certainly closed
    req.timeout = std::chrono::seconds(2);
    HttpResponse resp = client.sendRequest(req);

    CHECK_FALSE(resp.success);
    CHECK_TRUE(!resp.error.empty());

    client.shutdown();
}

#ifdef HAVE_OPENSSL

// --- HTTPS tests ---

LETHE_TEST_CASE(HttpLive_TlsGet_SelfSigned) {
    // Generate a self-signed cert.
    std::string certPem, keyPem;
    CHECK_TRUE(generateSelfSignedCert(certPem, keyPem));

    TestHttpsServer server;
    CHECK_TRUE(server.start(certPem, keyPem, 0));
    server.setHandler([](const std::string& req) {
        (void)req;
        return buildHttpResponse(200, "OK", "Hello over TLS!");
    });

    // Disable cert verification for the self-signed cert.
    TLSConfig tls;
    tls.setVerifyCertificates(false);
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    HttpRequest req;
    req.url = "https://127.0.0.1:" + std::to_string(server.port()) + "/secure";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    std::string body(resp.body.begin(), resp.body.end());
    CHECK_EQ(body, "Hello over TLS!");

    client.shutdown();
}

LETHE_TEST_CASE(HttpLive_TlsPost_SelfSigned) {
    std::string certPem, keyPem;
    CHECK_TRUE(generateSelfSignedCert(certPem, keyPem));

    std::string receivedBody;
    TestHttpsServer server;
    CHECK_TRUE(server.start(certPem, keyPem, 0));
    server.setHandler([&receivedBody](const std::string& req) {
        size_t blankLine = req.find("\r\n\r\n");
        if (blankLine != std::string::npos) {
            receivedBody = req.substr(blankLine + 4);
        }
        return buildHttpResponse(200, "OK", "tls post ok");
    });

    TLSConfig tls;
    tls.setVerifyCertificates(false);
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    HttpRequest req;
    req.url = "https://127.0.0.1:" + std::to_string(server.port()) + "/submit";
    req.method = HttpMethod::POST;
    req.body = "secure=data";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    CHECK_EQ(receivedBody, "secure=data");

    client.shutdown();
}

#endif // HAVE_OPENSSL


// --- Live LLM search service tests (end-to-end over real HTTP) ---

LETHE_TEST_CASE(SearchLive_WebSearch_EndToEnd) {
    // A search engine that returns result links.
    TestHttpServer server;
    CHECK_TRUE(server.start(0));
    int port = server.port();
    // Use a path-qualified engine URL so result links (different path) are
    // not filtered out as "the search engine itself".
    std::string engineUrl = "http://127.0.0.1:" + std::to_string(port) + "/searchengine";

    server.setHandler([&port](const std::string& req) {
        if (req.find("/search") != std::string::npos) {
            // Return search results HTML with links to result pages.
            std::string html = "<html><body>";
            html += "<a href=\"http://127.0.0.1:" + std::to_string(port) + "/result1\">";
            html += "First Search Result</a>";
            html += "<a href=\"http://127.0.0.1:" + std::to_string(port) + "/result2\">";
            html += "Second Search Result</a>";
            html += "</body></html>";
            return buildHttpResponse(200, "OK", html, {{"Content-Type", "text/html"}});
        }
        // Fallback.
        return buildHttpResponse(404, "Not Found", "not found");
    });

    TLSConfig tls;
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    llm::SearchConfig config;
    config.searchEngineUrl = engineUrl;
    config.useVpn = false;

    llm::SearchService search;
    CHECK_TRUE(search.initialize(&client, nullptr, config));

    auto results = search.webSearch("test query");
    CHECK_TRUE(results.size() >= 2);
    CHECK_EQ(results[0].title, "First Search Result");
    CHECK_EQ(results[1].title, "Second Search Result");
    CHECK_TRUE(results[0].url.find("/result1") != std::string::npos);

    client.shutdown();
}

LETHE_TEST_CASE(SearchLive_ReadPage_EndToEnd) {
    // A web server with a readable page.
    TestHttpServer server;
    CHECK_TRUE(server.start(0));
    int port = server.port();

    server.setHandler([&port](const std::string& req) {
        if (req.find("/article") != std::string::npos) {
            std::string html = "<html><head><title>My Test Article</title></head><body>";
            html += "<h1>Welcome</h1>";
            html += "<p>This is the article body text for the live read test.</p>";
            html += "</body></html>";
            return buildHttpResponse(200, "OK", html, {{"Content-Type", "text/html"}});
        }
        return buildHttpResponse(404, "Not Found", "not found");
    });

    TLSConfig tls;
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));

    llm::SearchConfig config;
    config.searchEngineUrl = "http://127.0.0.1:" + std::to_string(port);
    config.useVpn = false;

    llm::SearchService search;
    CHECK_TRUE(search.initialize(&client, nullptr, config));

    auto page = search.readPage("http://127.0.0.1:" + std::to_string(port) + "/article");
    CHECK_TRUE(page.success);
    CHECK_EQ(page.statusCode, 200);
    CHECK_EQ(page.title, "My Test Article");
    // The extracted text should contain the article body.
    CHECK_TRUE(page.textContent.find("article body text") != std::string::npos);

    client.shutdown();
}

