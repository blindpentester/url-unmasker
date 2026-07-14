/* URL-Unmasker: HTTP/HTTPS redirect walker with SSRF protection */
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>

constexpr int SOCKET_TIMEOUT_SECS = 5;
constexpr size_t MAX_HEADER_SIZE = 256 * 1024;
constexpr size_t RECV_BUFFER_SIZE = 4096;
constexpr int MAX_REDIRECT_HOPS = 15;

static bool is_private_ip(std::string_view ip) {
    if (ip.rfind("127.", 0) == 0) return true;
    if (ip.rfind("10.", 0) == 0) return true;
    if (ip.rfind("192.168.", 0) == 0) return true;
    if (ip.rfind("169.254.", 0) == 0) return true;
    if (ip.rfind("172.", 0) == 0) {
        size_t dot = ip.find('.', 4);
        if (dot != std::string::npos) {
            try {
                int octet = std::stoi(std::string(ip.substr(4, dot - 4)));
                if (octet >= 16 && octet <= 31) return true;
            } catch (...) {}
        }
    }
    if (ip == "::1") return true;
    if (ip.rfind("fc00:", 0) == 0) return true;
    if (ip.rfind("fe80:", 0) == 0) return true;
    if (ip.rfind("::ffff:127.", 0) == 0) return true;
    return false;
}

struct Socket {
    int fd_{-1};
    explicit Socket(int fd) : fd_(fd) {}
    ~Socket() { if (fd_ >= 0) ::close(fd_); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Socket& operator=(Socket&& o) noexcept {
        if (this != &o) { if (fd_ >= 0) ::close(fd_); fd_ = o.fd_; o.fd_ = -1; }
        return *this;
    }
};

struct AddrInfoDeleter {
    void operator()(addrinfo* ai) const noexcept { if (ai) freeaddrinfo(ai); }
};
using AddrInfoPtr = std::unique_ptr<addrinfo, AddrInfoDeleter>;

struct TlsSession {
    SSL_CTX* ctx_{nullptr};
    SSL* ssl_{nullptr};
    Socket sock_;
    explicit TlsSession(Socket&& s) noexcept : sock_(std::move(s)) {}
    ~TlsSession() { shutdown(); }
    bool init(std::string_view host);
    bool send_all(std::string_view data);
    bool recv_headers(std::string& out);
private:
    void shutdown();
};

bool TlsSession::init(std::string_view host) {
    if (host.empty()) { std::cerr << "[ERROR] Empty hostname\n"; return false; }
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) { std::cerr << "[ERROR] SSL context\n"; return false; }
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    ssl_ = SSL_new(ctx_);
    if (!ssl_) { std::cerr << "[ERROR] SSL object\n"; SSL_CTX_free(ctx_); ctx_ = nullptr; return false; }
    SSL_set_fd(ssl_, sock_.fd_);
    SSL_set_tlsext_host_name(ssl_, host.data());
    if (SSL_connect(ssl_) != 1) { std::cerr << "[ERROR] TLS handshake\n"; SSL_free(ssl_); ssl_ = nullptr; return false; }
    return true;
}

bool TlsSession::send_all(std::string_view data) {
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
    size_t left = data.size();
    while (left > 0) {
        int n = SSL_write(ssl_, ptr, static_cast<int>(left));
        if (n <= 0) { std::cerr << "[ERROR] SSL_write\n"; return false; }
        ptr += n;
        left -= n;
    }
    return true;
}

bool TlsSession::recv_headers(std::string& out) {
    out.clear();
    char buf[RECV_BUFFER_SIZE];
    while (out.find("\r\n\r\n") == std::string::npos && out.size() < MAX_HEADER_SIZE) {
        int n = SSL_read(ssl_, buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    auto pos = out.find("\r\n\r\n");
    if (pos != std::string::npos) {
        out.resize(pos + 4);
        return true;
    }
    return false;
}

void TlsSession::shutdown() {
    if (ssl_) { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
    if (ctx_) { SSL_CTX_free(ctx_); ctx_ = nullptr; }
}

struct ParsedUrl {
    std::string scheme, host, port, path;
};

static std::optional<ParsedUrl> parse_url(std::string_view url) {
    static const std::regex re(R"(^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/\s:]+)(?::([0-9]+))?(/.*)?$)");
    std::smatch m;
    std::string url_str(url);
    if (!std::regex_match(url_str, m, re)) return std::nullopt;
    ParsedUrl p{m[1].str(), m[2].str(),
                m[3].matched ? m[3].str() : (m[1] == "https" ? "443" : "80"),
                m[4].matched ? m[4].str() : "/"};
    return p;
}

static std::optional<std::string> resolve_ip(std::string_view host, std::string_view port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res_ptr = nullptr;
    int err = getaddrinfo(host.data(), port.data(), &hints, &res_ptr);
    if (err != 0) {
        std::cerr << "[ERROR] getaddrinfo: " << gai_strerror(err) << "\n";
        return std::nullopt;
    }
    AddrInfoPtr res{res_ptr};
    char buf[INET6_ADDRSTRLEN];
    for (addrinfo* p = res.get(); p; p = p->ai_next) {
        void* addr = nullptr;
        if (p->ai_family == AF_INET) {
            addr = &reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr;
        } else if (p->ai_family == AF_INET6) {
            addr = &reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr;
        } else {
            continue;
        }
        if (inet_ntop(p->ai_family, addr, buf, sizeof(buf))) {
            return std::string{buf};
        }
    }
    return std::nullopt;
}

static std::optional<Socket> connect_tcp(std::string_view host, std::string_view port, std::string& out_ip) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res_ptr = nullptr;
    int err = getaddrinfo(host.data(), port.data(), &hints, &res_ptr);
    if (err != 0) {
        std::cerr << "[ERROR] getaddrinfo: " << gai_strerror(err) << "\n";
        return std::nullopt;
    }
    AddrInfoPtr res{res_ptr};
    for (addrinfo* p = res.get(); p; p = p->ai_next) {
        int fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv{SOCKET_TIMEOUT_SECS, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            void* addr = nullptr;
            if (p->ai_family == AF_INET) {
                addr = &reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr;
            } else {
                addr = &reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr;
            }
            char buf[INET6_ADDRSTRLEN];
            if (!inet_ntop(p->ai_family, addr, buf, sizeof(buf))) {
                ::close(fd);
                continue;
            }
            if (is_private_ip(buf)) {
                std::cerr << "[BLOCKED] SSRF to " << buf << "\n";
                ::close(fd);
                continue;
            }
            out_ip = buf;
            return Socket{fd};
        }
        ::close(fd);
    }
    return std::nullopt;
}

static bool http_head_once(const ParsedUrl& u, std::string& headers, std::string& used_ip, bool& tls_used) {
    headers.clear();
    used_ip.clear();
    tls_used = false;
    std::ostringstream req;
    req << "HEAD " << u.path << " HTTP/1.1\r\n";
    req << "Host: " << u.host;
    bool default_port = (u.scheme == "https" && u.port == "443") || (u.scheme == "http" && u.port == "80");
    if (!default_port) req << ":" << u.port;
    req << "\r\nConnection: close\r\n\r\n";
    std::string request = req.str();

    if (u.scheme == "https") {
        auto sock_opt = connect_tcp(u.host, u.port, used_ip);
        if (!sock_opt) return false;
        TlsSession tls{std::move(*sock_opt)};
        if (!tls.init(u.host)) return false;
        tls_used = true;
        if (!tls.send_all(request)) return false;
        return tls.recv_headers(headers);
    } else {
        auto sock_opt = connect_tcp(u.host, u.port, used_ip);
        if (!sock_opt) return false;
        Socket s{std::move(*sock_opt)};
        const char* p = request.data();
        size_t left = request.size();
        while (left > 0) {
            ssize_t n = ::send(s.fd_, p, left, 0);
            if (n <= 0) return false;
            p += n;
            left -= n;
        }
        std::string tmp;
        char buf[RECV_BUFFER_SIZE];
        while (tmp.find("\r\n\r\n") == std::string::npos && tmp.size() < MAX_HEADER_SIZE) {
            ssize_t n = ::recv(s.fd_, buf, sizeof(buf), 0);
            if (n <= 0) break;
            tmp.append(buf, static_cast<size_t>(n));
        }
        auto pos = tmp.find("\r\n\r\n");
        if (pos != std::string::npos) {
            headers = tmp.substr(0, pos + 4);
            return true;
        }
        return false;
    }
}

static std::string resolve_relative(const ParsedUrl& base, std::string_view loc) {
    auto rel_opt = parse_url(loc);
    if (rel_opt) return std::string{loc};
    std::ostringstream oss;
    oss << base.scheme << "://" << base.host;
    bool default_port = (base.scheme == "https" && base.port == "443") || (base.scheme == "http" && base.port == "80");
    if (!default_port) oss << ':' << base.port;
    if (!loc.empty() && loc[0] == '/') {
        oss << loc;
        return oss.str();
    }
    std::string parent = base.path;
    auto slash = parent.rfind('/');
    if (slash != std::string::npos) {
        parent.erase(slash + 1);
    } else {
        parent.clear();
    }
    oss << parent << loc;
    return oss.str();
}

struct Hop {
    int status{};
    std::string location, ip_used, next_url;
};

static bool follow_redirects(const std::string& start_url, std::string& final_url, std::string& final_ip, std::vector<Hop>& hops) {
    hops.clear();
    std::set<std::string> seen;
    std::string current = start_url;
    for (int i = 0; i < MAX_REDIRECT_HOPS; ++i) {
        auto parsed_opt = parse_url(current);
        if (!parsed_opt) {
            final_url = current;
            return false;
        }
        const ParsedUrl& u = *parsed_opt;
        std::string headers, ip;
        bool tls_used{};
        if (!http_head_once(u, headers, ip, tls_used)) {
            final_url = current;
            final_ip = ip;
            return false;
        }
        int status{0};
        {
            std::istringstream ss(headers);
            std::string ver;
            ss >> ver >> status;
        }
        std::string loc;
        {
            std::istringstream hs(headers);
            std::string line;
            while (std::getline(hs, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                std::string lower = line;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower.size() >= 9 && lower.substr(0, 9) == "location:") {
                    loc = line.substr(9);
                    for (char& c : loc) {
                        if (c == '\r' || c == '\n') c = ' ';
                    }
                    auto first = loc.find_first_not_of(" \t");
                    if (first != std::string::npos) loc.erase(0, first);
                    break;
                }
            }
        }
        Hop h{status, loc, ip, ""};
        if (status >= 300 && status < 400 && !loc.empty()) {
            std::string next = resolve_relative(u, loc);
            auto nxt_parsed = parse_url(next);
            if (!nxt_parsed || (nxt_parsed->scheme != "http" && nxt_parsed->scheme != "https")) {
                std::cerr << "[BLOCKED] Non-HTTP: " << next << "\n";
                final_url = current;
                final_ip = ip;
                hops.push_back(h);
                return true;
            }
            h.next_url = next;
            hops.push_back(h);
            if (!seen.insert(next).second) {
                final_url = next;
                auto pu_opt = parse_url(next);
                if (pu_opt) final_ip = resolve_ip(pu_opt->host, pu_opt->port).value_or(std::string{});
                return true;
            }
            current = next;
            continue;
        } else {
            final_url = current;
            final_ip = ip;
            hops.push_back(h);
            return true;
        }
    }
    std::cerr << "[WARN] Max redirects exceeded\n";
    auto pu_opt = parse_url(current);
    if (pu_opt) final_ip = resolve_ip(pu_opt->host, pu_opt->port).value_or(std::string{});
    final_url = current;
    return true;
}

static void print_result(const std::string& source) {
    std::string final_url, final_ip;
    std::vector<Hop> hops;
    bool ok = follow_redirects(source, final_url, final_ip, hops);
    std::cout << "\n[Source]      " << source << "\n";
    if (!final_ip.empty()) {
        std::cout << "[Resolved IP] " << final_ip << "\n";
    } else {
        std::cout << "[Resolved IP] (unknown)\n";
    }
    std::cout << "[Final URL]   " << final_url << "\n";
    if (!hops.empty()) {
        std::cout << "[Hops]\n";
        int idx = 1;
        for (const auto& h : hops) {
            std::cout << "  " << idx++ << ") " << h.status;
            if (!h.location.empty()) std::cout << " -> " << h.location;
            if (!h.ip_used.empty()) std::cout << " [" << h.ip_used << "]";
            if (!h.next_url.empty()) std::cout << "\n     next: " << h.next_url;
            std::cout << "\n";
        }
    }
    if (!ok) std::cout << "[Note] Request failed\n";
    std::cout.flush();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <url1> [url2 ...]\n";
        return 1;
    }
    for (int i = 1; i < argc; ++i) {
        print_result(argv[i]);
        if (i + 1 < argc) std::cout << "----------------------------------------\n";
    }
    return 0;
}
