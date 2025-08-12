// unmask.cpp
// HTTP/HTTPS redirect unmasker via HEAD requests.
// - No content fetched; headers only.
// - DNS -> IP, follows up to 15 redirects.
// - HTTPS via OpenSSL (open-source). Certificate verification is OFF by default
//   to avoid external CA dependencies; you can enable it with VERIFY_TLS=1.

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>

struct ParsedUrl {
    std::string scheme; // http/https
    std::string host;
    std::string port;   // default 80/443
    std::string path;   // starts with '/'
    bool valid{false};
};

struct Hop {
    int status{};
    std::string location;
    std::string ip_used;
    std::string next_url;
};

static ParsedUrl parse_url(const std::string& url) {
    static const std::regex re(R"(^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/\s:]+)(?::([0-9]+))?(/.*)?$)");
    std::smatch m;
    ParsedUrl p;
    if (!std::regex_match(url, m, re)) return p;
    p.scheme = m[1].str();
    p.host   = m[2].str();
    p.port   = m[3].matched ? m[3].str() : (p.scheme == "https" ? "443" : "80");
    p.path   = m[4].matched ? m[4].str() : "/";
    p.valid  = (p.scheme == "http" || p.scheme == "https");
    return p;
}

static bool resolve_ip(const std::string& host, const std::string& port, std::string& out_ip) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0) return false;
    char buf[INET6_ADDRSTRLEN]{0};
    for (addrinfo* p = res; p; p = p->ai_next) {
        void* addr = nullptr;
        if (p->ai_family == AF_INET) addr = &((sockaddr_in*)p->ai_addr)->sin_addr;
        else if (p->ai_family == AF_INET6) addr = &((sockaddr_in6*)p->ai_addr)->sin6_addr;
        else continue;
        if (inet_ntop(p->ai_family, addr, buf, sizeof(buf))) {
            out_ip = buf;
            freeaddrinfo(res);
            return true;
        }
    }
    freeaddrinfo(res);
    return false;
}

static int connect_tcp(const std::string& host, const std::string& port, std::string* used_ip=nullptr) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return -1;

    int sock = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            if (used_ip) {
                char buf[INET6_ADDRSTRLEN]{0};
                if (p->ai_family == AF_INET) {
                    inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, buf, sizeof(buf));
                } else if (p->ai_family == AF_INET6) {
                    inet_ntop(AF_INET6, &((sockaddr_in6*)p->ai_addr)->sin6_addr, buf, sizeof(buf));
                }
                *used_ip = buf;
            }
            freeaddrinfo(res);
            return sock;
        }
        ::close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return -1;
}

static bool recv_headers_plain(int fd, std::string& headers) {
    headers.clear();
    constexpr size_t MAX = 256 * 1024;
    char buf[4096];
    while (headers.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        headers.append(buf, buf + n);
        if (headers.size() > MAX) break;
    }
    auto pos = headers.find("\r\n\r\n");
    if (pos != std::string::npos) { headers.resize(pos + 4); return true; }
    return false;
}

static bool send_all_plain(int fd, const std::string& data) {
    const char* p = data.data();
    size_t left = data.size();
    while (left) {
        ssize_t n = ::send(fd, p, left, 0);
        if (n <= 0) return false;
        p += n; left -= n;
    }
    return true;
}

// --- TLS helpers (OpenSSL) ---
struct TlsSession {
    SSL_CTX* ctx{nullptr};
    SSL* ssl{nullptr};
    int fd{-1};
    std::string ip;
};

static bool tls_init_once() {
    static bool inited = false;
    if (!inited) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        inited = true;
    }
    return true;
}

static bool tls_connect(const std::string& host, const std::string& port, TlsSession& out) {
    tls_init_once();
    out.ctx = SSL_CTX_new(TLS_client_method());
    if (!out.ctx) return false;

#if VERIFY_TLS
    SSL_CTX_set_verify(out.ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(out.ctx);
#else
    // No verification: we’re inspecting headers only, not trusting identity.
    SSL_CTX_set_verify(out.ctx, SSL_VERIFY_NONE, nullptr);
#endif

    out.fd = connect_tcp(host, port, &out.ip);
    if (out.fd < 0) { SSL_CTX_free(out.ctx); out.ctx = nullptr; return false; }

    out.ssl = SSL_new(out.ctx);
    if (!out.ssl) { ::close(out.fd); SSL_CTX_free(out.ctx); out.fd = -1; out.ctx = nullptr; return false; }

    SSL_set_fd(out.ssl, out.fd);
    // SNI
    SSL_set_tlsext_host_name(out.ssl, host.c_str());

    if (SSL_connect(out.ssl) != 1) {
        SSL_free(out.ssl); ::close(out.fd); SSL_CTX_free(out.ctx);
        out.ssl = nullptr; out.fd = -1; out.ctx = nullptr;
        return false;
    }
    return true;
}

static void tls_close(TlsSession& s) {
    if (s.ssl) { SSL_shutdown(s.ssl); SSL_free(s.ssl); s.ssl = nullptr; }
    if (s.fd >= 0) { ::close(s.fd); s.fd = -1; }
    if (s.ctx) { SSL_CTX_free(s.ctx); s.ctx = nullptr; }
}

static bool tls_send_all(TlsSession& s, const std::string& data) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());
    size_t left = data.size();
    while (left) {
        int n = SSL_write(s.ssl, p, (int)left);
        if (n <= 0) return false;
        p += n; left -= n;
    }
    return true;
}

static bool tls_recv_headers(TlsSession& s, std::string& headers) {
    headers.clear();
    constexpr size_t MAX = 256 * 1024;
    char buf[4096];
    while (headers.find("\r\n\r\n") == std::string::npos) {
        int n = SSL_read(s.ssl, buf, sizeof(buf));
        if (n <= 0) break;
        headers.append(buf, buf + n);
        if (headers.size() > MAX) break;
    }
    auto pos = headers.find("\r\n\r\n");
    if (pos != std::string::npos) { headers.resize(pos + 4); return true; }
    return false;
}

// --- Core redirect walker ---
static std::string build_hostport(const ParsedUrl& u) {
    bool default_port = (u.scheme == "https" ? (u.port == "443") : (u.port == "80"));
    return u.host + (default_port ? "" : (":" + u.port));
}

static bool http_head_once(const ParsedUrl& u, std::string& out_headers, std::string& out_ip, bool& out_tls) {
    out_headers.clear(); out_ip.clear(); out_tls = false;

    // Build request
    std::ostringstream req;
    req << "HEAD " << u.path << " HTTP/1.1\r\n"
        << "Host: " << build_hostport(u) << "\r\n"
        << "User-Agent: Unmasker/1.1\r\n"
        << "Accept: */*\r\n"
        << "Connection: close\r\n\r\n";
    std::string r = req.str();

    if (u.scheme == "https") {
        TlsSession s;
        if (!tls_connect(u.host, u.port, s)) return false;
        out_ip = s.ip; out_tls = true;
        bool ok = tls_send_all(s, r) && tls_recv_headers(s, out_headers);
        tls_close(s);
        return ok;
    } else {
        std::string ip;
        int fd = connect_tcp(u.host, u.port, &ip);
        if (fd < 0) return false;
        out_ip = ip; out_tls = false;
        bool ok = send_all_plain(fd, r) && recv_headers_plain(fd, out_headers);
        ::close(fd);
        return ok;
    }
}

static std::string resolve_relative(const ParsedUrl& base, const std::string& loc) {
    ParsedUrl abs = parse_url(loc);
    if (abs.valid) return loc; // already absolute
    if (!loc.empty() && loc[0] == '/') {
        return base.scheme + "://" + base.host + ((base.scheme=="https"&&base.port=="443")||(base.scheme=="http"&&base.port=="80") ? "" : (":" + base.port)) + loc;
    }
    // relative without leading slash
    std::string parent = base.path;
    auto slash = parent.rfind('/');
    if (slash != std::string::npos) parent = parent.substr(0, slash + 1);
    else parent = "/";
    return base.scheme + "://" + base.host + ((base.scheme=="https"&&base.port=="443")||(base.scheme=="http"&&base.port=="80") ? "" : (":" + base.port)) + parent + loc;
}

static bool follow_redirects(const std::string& start_url,
                             std::string& final_url,
                             std::string& final_ip,
                             std::vector<Hop>& hops,
                             int max_hops = 15) {
    hops.clear();
    std::set<std::string> seen;
    std::string current = start_url;

    for (int i = 0; i < max_hops; ++i) {
        ParsedUrl u = parse_url(current);
        if (!u.valid) { final_url = current; return false; }

        std::string headers, ip;
        bool used_tls = false;
        if (!http_head_once(u, headers, ip, used_tls)) {
            final_url = current; final_ip = ip; return false;
        }

        // Parse status
        int status = 0;
        {
            std::istringstream ss(headers);
            std::string httpver;
            ss >> httpver >> status;
        }

        // Extract Location
        std::string location;
        {
            std::istringstream hs(headers);
            std::string line;
            while (std::getline(hs, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                // Case-insensitive "Location:"
                if (line.size() >= 9 && strncasecmp(line.c_str(), "Location:", 9) == 0) {
                    std::string val = line.substr(9);
                    // trim leading spaces
                    size_t start = val.find_first_not_of(" \t");
                    if (start != std::string::npos) val = val.substr(start);
                    location = val;
                    break;
                }
            }
        }

        Hop h;
        h.status = status;
        h.location = location;
        h.ip_used = ip;

        if (status >= 300 && status < 400 && !location.empty()) {
            std::string next = resolve_relative(u, location);
            h.next_url = next;
            hops.push_back(h);

            if (!seen.insert(next).second) {
                // loop
                final_url = next;
                ParsedUrl pu = parse_url(next);
                std::string lip;
                resolve_ip(pu.host, pu.port, lip);
                final_ip = lip;
                return true;
            }
            current = next;
            continue;
        } else {
            // Final landing (non-redirect or redirect with no Location)
            final_url = current;
            final_ip  = ip;
            hops.push_back(h);
            return true;
        }
    }

    // Hop limit exceeded – report best-known
    ParsedUrl pu = parse_url(current);
    std::string lip;
    resolve_ip(pu.host, pu.port, lip);
    final_url = current; final_ip = lip;
    return true;
}

static void print_result(const std::string& source) {
    std::string final_url, final_ip;
    std::vector<Hop> hops;
    bool ok = follow_redirects(source, final_url, final_ip, hops);

    std::cout << "[Source] " << source << "\n";
    if (!final_ip.empty()) std::cout << "[Resolved IP] " << final_ip << "\n";
    else std::cout << "[Resolved IP] (unavailable)\n";
    std::cout << "[Final URL] " << final_url << "\n";

    if (!hops.empty()) {
        std::cout << "[Hops]\n";
        int i = 1;
        for (const auto& h : hops) {
            std::cout << "  " << i++ << ") " << h.status;
            if (!h.location.empty()) std::cout << " -> " << h.location;
            if (!h.ip_used.empty()) std::cout << "  [ip:" << h.ip_used << "]";
            if (!h.next_url.empty()) std::cout << "\n     next: " << h.next_url;
            std::cout << "\n";
        }
    }
    if (!ok) std::cout << "[Note] Request failed or truncated. Results may be partial.\n";
    std::cout << std::flush;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <url1> [url2 ...]\n";
        std::cerr << "Follows HTTP/HTTPS redirects (HEAD only). Prints Source/IP/Final URL.\n";
        return 1;
    }
    for (int i = 1; i < argc; ++i) {
        print_result(argv[i]);
        if (i + 1 < argc) std::cout << "----------------------------------------\n";
    }
    return 0;
}
